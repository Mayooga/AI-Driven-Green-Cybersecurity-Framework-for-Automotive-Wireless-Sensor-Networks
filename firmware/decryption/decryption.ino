/*
 * receiver.ino — ESP2 (Node B): ESP-NOW -> AES-128-GCM verify/decrypt -> Serial
 * Packet: [IV 12 | ciphertext PAYLOAD_LEN | tag 16]
 */

#include <esp_now.h>
#include <WiFi.h>
#include <mbedtls/gcm.h>
#include <Preferences.h>
#include "esp_mac.h"          // on core 2.x use "esp_system.h"
#include "secrets.h"          // aesKey[16] (same as sender)
#include "sensor_payload.h"   // SensorPayload, PAYLOAD_LEN (same as sender)

#define PACKET_LEN (12 + PAYLOAD_LEN + 16)
#define MAX_TRACKED_SOURCES 8
#define RX_LIMIT_PER_SECOND 100
#define RX_GLOBAL_LIMIT_PER_SECOND 100

mbedtls_gcm_context gcm;

struct RxItem {
  uint8_t data[PACKET_LEN];
  int8_t  rssi;
  uint32_t t_ms;
};
QueueHandle_t rxQueue;

volatile uint32_t statRx = 0, statRateLimited = 0, statGlobalLimited = 0,
                  statQueueDrop = 0, statBadLen = 0, statUntrustedDrop = 0;
uint32_t statOk = 0, statAuthFail = 0, statLost = 0, statDecryptUs = 0,
         statReplay = 0, statAccepted = 0, statReplayStoreFail = 0;
struct __attribute__((packed)) ReplayState {
  uint16_t lastSeq;
  uint8_t valid;
};
Preferences replayStore;
bool haveSeq = false;
uint16_t lastSeq = 0;
uint32_t processedPackets = 0;
// Provisioned sender station MAC. The sender sketch prints this at startup.
const uint8_t trustedSenderMac[6] = {0x8C, 0x94, 0xDF, 0x6B, 0xF1, 0x30};

struct SourceRateWindow {
  uint8_t mac[6];
  uint32_t windowStart;
  uint32_t lastSeen;
  uint16_t count;
  bool used;
};
SourceRateWindow sourceRates[MAX_TRACKED_SOURCES] = {};
uint32_t globalWindowStart = 0;
uint16_t globalWindowCount = 0;

// Bound work from any one radio source before it can fill the packet queue.
// The legitimate sender normally emits at most one packet per second.
bool allowSourcePacket(const uint8_t *mac, uint32_t now) {
  if ((uint32_t)(now - globalWindowStart) >= 1000) {
    globalWindowStart = now;
    globalWindowCount = 0;
  }
  if (globalWindowCount >= RX_GLOBAL_LIMIT_PER_SECOND) {
    statGlobalLimited++;
    return false;
  }
  globalWindowCount++;

  int slot = -1;
  int oldestSlot = 0;

  for (int i = 0; i < MAX_TRACKED_SOURCES; ++i) {
    if (sourceRates[i].used && memcmp(sourceRates[i].mac, mac, 6) == 0) {
      slot = i;
      break;
    }
    if (!sourceRates[i].used) {
      slot = i;
      break;
    }
    if ((int32_t)(sourceRates[i].lastSeen -
                  sourceRates[oldestSlot].lastSeen) < 0) {
      oldestSlot = i;
    }
  }

  if (slot < 0) slot = oldestSlot;
  SourceRateWindow &entry = sourceRates[slot];
  if (!entry.used || memcmp(entry.mac, mac, 6) != 0) {
    memcpy(entry.mac, mac, 6);
    entry.windowStart = now;
    entry.lastSeen = now;
    entry.count = 0;
    entry.used = true;
  }

  if ((uint32_t)(now - entry.windowStart) >= 1000) {
    entry.windowStart = now;
    entry.count = 0;
  }
  entry.lastSeen = now;
  if (entry.count >= RX_LIMIT_PER_SECOND) {
    statRateLimited++;
    return false;
  }
  entry.count++;
  return true;
}

#if ESP_ARDUINO_VERSION_MAJOR >= 3
void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  const uint8_t *srcMac = info->src_addr;
  int8_t rssi = info->rx_ctrl ? info->rx_ctrl->rssi : 0;
#else
void onRecv(const uint8_t *mac, const uint8_t *data, int len) {
  const uint8_t *srcMac = mac;
  int8_t rssi = 0;
#endif
  statRx++;
  if (memcmp(srcMac, trustedSenderMac, sizeof(trustedSenderMac)) != 0) {
    statUntrustedDrop++;
    return;
  }
  uint32_t now = millis();
  if (!allowSourcePacket(srcMac, now)) return;
  if (len != PACKET_LEN) { statBadLen++; return; }
  RxItem item;
  memcpy(item.data, data, PACKET_LEN);
  item.rssi = rssi;
  item.t_ms = now;
  if (xQueueSend(rxQueue, &item, 0) != pdTRUE) statQueueDrop++;
}

void setup() {
  Serial.begin(115200);
  replayStore.begin("wsnseq", false);
  ReplayState savedState = {};
  if (replayStore.getBytes("replay", &savedState, sizeof(savedState)) == sizeof(savedState) &&
      savedState.valid == 1) {
    haveSeq = true;
    lastSeq = savedState.lastSeq;
  }
  WiFi.mode(WIFI_STA);

  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  Serial.printf("# Receiver MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  if (esp_now_init() != ESP_OK) {
    Serial.println("# ESP-NOW init failed");
    return;
  }
  if (esp_now_set_pmk(espNowPmk) != ESP_OK) {
    Serial.println("# ESP-NOW PMK setup failed");
    return;
  }
  esp_now_peer_info_t senderPeer = {};
  memcpy(senderPeer.peer_addr, trustedSenderMac, sizeof(trustedSenderMac));
  senderPeer.ifidx = WIFI_IF_STA;
  senderPeer.channel = 0;
  senderPeer.encrypt = true;
  memcpy(senderPeer.lmk, espNowLmk, sizeof(senderPeer.lmk));
  if (esp_now_add_peer(&senderPeer) != ESP_OK) {
    Serial.println("# ESP-NOW encrypted sender peer setup failed");
    return;
  }
  rxQueue = xQueueCreate(16, sizeof(RxItem));

  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);

  esp_now_register_recv_cb(onRecv);
  Serial.printf("# Receiver ready. payload=%dB packet=%dB\n", PAYLOAD_LEN, PACKET_LEN);
  Serial.println("# t_ms,seq,auth_ok,len,rssi,iat_ms,current,temp,hum,press,pir,replay");
}

void loop() {
  RxItem item;
  static uint32_t lastArr = 0;

  if (xQueueReceive(rxQueue, &item, pdMS_TO_TICKS(1000)) == pdTRUE) {
    processedPackets++;
    uint32_t iat = lastArr ? item.t_ms - lastArr : 0;
    lastArr = item.t_ms;

    const uint8_t *iv         = item.data;
    const uint8_t *ciphertext = item.data + 12;
    const uint8_t *tag        = item.data + 12 + PAYLOAD_LEN;

    SensorPayload p;
    uint32_t t = micros();
    int rc = mbedtls_gcm_auth_decrypt(&gcm, PAYLOAD_LEN, iv, 12, NULL, 0,
                                      tag, 16, ciphertext, (uint8_t*)&p);
    statDecryptUs += micros() - t;

    if (rc != 0) {
      statAuthFail++;
      Serial.printf("%lu,-1,0,%d,%d,%lu,0,0,0,0,0,0\n",
                    (unsigned long)item.t_ms, PACKET_LEN, item.rssi, (unsigned long)iat);
    } else {
      statOk++;
      uint16_t seqDelta = 0;
      bool replay = false;

      if (haveSeq) {
        seqDelta = (uint16_t)(p.seq - lastSeq);
        replay = seqDelta == 0 || seqDelta >= 0x8000;
      }

      if (replay) {
        statReplay++;
        // Keep this row as an audit/training event, but do not count or use it
        // as accepted sensor telemetry. replay=1 is the rejection indicator.
      } else {
        if (haveSeq && seqDelta > 1 && seqDelta < 1000) {
          statLost += seqDelta - 1;
        }
        // Commit the replay watermark before exposing this reading as accepted.
        // This survives receiver power loss; the sender reserves sequence blocks
        // in NVS so it will not reuse counters after its own reboot.
        ReplayState nextState = {p.seq, 1};
        if (replayStore.putBytes("replay", &nextState, sizeof(nextState)) == sizeof(nextState)) {
          haveSeq = true;
          lastSeq = p.seq;
          statAccepted++;
        } else {
          statReplayStoreFail++;
          Serial.println("# SECURITY: replay state could not be saved; reading withheld");
          return;
        }
      }

      // Preserve the packet fields for capture.py. Downstream consumers must
      // treat replay=1 as rejected, even though it is logged for audit/training.
      Serial.printf("%lu,%u,1,%d,%d,%lu,%u,%.2f,%.2f,%.1f,%u,%u\n",
                    (unsigned long)item.t_ms, p.seq, PACKET_LEN, item.rssi, (unsigned long)iat,
                    p.current_raw, p.temp_x100 / 100.0, p.hum_x100 / 100.0,
                    p.press_x10 / 10.0, p.pir, replay ? 1 : 0);
    }

    if (processedPackets % 10 == 0) {
      Serial.printf("# STATS rx=%lu ok=%lu accepted=%lu replay=%lu authfail=%lu badlen=%lu untrusted=%lu rate_limited=%lu global_limited=%lu queue_drops=%lu replay_store_fail=%lu lost=%lu avg_decrypt_us=%lu\n",
                    (unsigned long)statRx, (unsigned long)statOk, (unsigned long)statAccepted,
                    (unsigned long)statReplay, (unsigned long)statAuthFail,
                    (unsigned long)statBadLen, (unsigned long)statUntrustedDrop,
                    (unsigned long)statRateLimited,
                    (unsigned long)statGlobalLimited, (unsigned long)statQueueDrop,
                    (unsigned long)statReplayStoreFail,
                    (unsigned long)statLost,
                    (unsigned long)(statOk ? statDecryptUs / statOk : 0));
    }
  }
}
