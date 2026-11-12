/*
 * receiver.ino — ESP2 (Node B): ESP-NOW -> AES-128-GCM verify/decrypt -> Serial
 * Packet: [IV 12 | ciphertext PAYLOAD_LEN | tag 16]
 */

#include <esp_now.h>
#include <WiFi.h>
#include <mbedtls/gcm.h>
#include "esp_mac.h"          // on core 2.x use "esp_system.h"
#include "secrets.h"          // aesKey[16] (same as sender)
#include "sensor_payload.h"   // SensorPayload, PAYLOAD_LEN (same as sender)

#define PACKET_LEN (12 + PAYLOAD_LEN + 16)

mbedtls_gcm_context gcm;

struct RxItem {
  uint8_t data[PACKET_LEN];
  int8_t  rssi;
  uint32_t t_ms;
};
QueueHandle_t rxQueue;

uint32_t statRx = 0, statOk = 0, statAuthFail = 0, statBadLen = 0,
         statLost = 0, statDecryptUs = 0, statReplay = 0, statAccepted = 0;
bool     haveSeq = false;
uint16_t lastSeq = 0;
uint32_t processedPackets = 0;

#if ESP_ARDUINO_VERSION_MAJOR >= 3
void onRecv(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  int8_t rssi = info->rx_ctrl ? info->rx_ctrl->rssi : 0;
#else
void onRecv(const uint8_t *mac, const uint8_t *data, int len) {
  int8_t rssi = 0;
#endif
  statRx++;
  if (len != PACKET_LEN) { statBadLen++; return; }
  RxItem item;
  memcpy(item.data, data, PACKET_LEN);
  item.rssi = rssi;
  item.t_ms = millis();
  xQueueSend(rxQueue, &item, 0);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);

  uint8_t mac[6];
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  Serial.printf("# Receiver MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  if (esp_now_init() != ESP_OK) {
    Serial.println("# ESP-NOW init failed");
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
      } else {
        if (haveSeq && seqDelta > 1 && seqDelta < 1000) {
          statLost += seqDelta - 1;
        }
        haveSeq = true;
        lastSeq = p.seq;
        statAccepted++;
      }

      Serial.printf("%lu,%u,1,%d,%d,%lu,%u,%.2f,%.2f,%.1f,%u,%u\n",
                    (unsigned long)item.t_ms, p.seq, PACKET_LEN, item.rssi, (unsigned long)iat,
                    p.current_raw, p.temp_x100 / 100.0, p.hum_x100 / 100.0,
                    p.press_x10 / 10.0, p.pir, replay ? 1 : 0);
    }

    if (processedPackets % 10 == 0) {
      Serial.printf("# STATS rx=%lu ok=%lu accepted=%lu replay=%lu authfail=%lu badlen=%lu lost=%lu avg_decrypt_us=%lu\n",
                    (unsigned long)statRx, (unsigned long)statOk, (unsigned long)statAccepted,
                    (unsigned long)statReplay, (unsigned long)statAuthFail,
                    (unsigned long)statBadLen, (unsigned long)statLost,
                    (unsigned long)(statOk ? statDecryptUs / statOk : 0));
    }
  }
}
