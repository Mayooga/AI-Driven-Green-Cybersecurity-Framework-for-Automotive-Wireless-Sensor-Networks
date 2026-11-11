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
};
QueueHandle_t rxQueue;

uint32_t statRx = 0, statOk = 0, statAuthFail = 0, statBadLen = 0,
         statLost = 0, statDecryptUs = 0;
bool     haveSeq = false;
uint16_t lastSeq = 0;

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
}

void loop() {
  RxItem item;
  if (xQueueReceive(rxQueue, &item, pdMS_TO_TICKS(1000)) == pdTRUE) {
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
      Serial.println("# AUTH FAIL: wrong key or tampered packet");
    } else {
      statOk++;
      if (haveSeq) {
        uint16_t gap = (uint16_t)(p.seq - lastSeq);
        if (gap > 1 && gap < 1000) statLost += gap - 1;
      }
      haveSeq = true;
      lastSeq = p.seq;
      Serial.printf("seq=%u cur=%u T=%.2f H=%.2f P=%.1f pir=%u rssi=%d\n",
                    p.seq, p.current_raw, p.temp_x100 / 100.0, p.hum_x100 / 100.0,
                    p.press_x10 / 10.0, p.pir, item.rssi);
    }
  }

  static uint32_t lastStat = 0;
  if (millis() - lastStat > 20000) {
    lastStat = millis();
    Serial.printf("# STATS rx=%lu ok=%lu authfail=%lu badlen=%lu lost=%lu avg_decrypt_us=%lu\n",
                  (unsigned long)statRx, (unsigned long)statOk, (unsigned long)statAuthFail,
                  (unsigned long)statBadLen, (unsigned long)statLost,
                  (unsigned long)(statOk ? statDecryptUs / statOk : 0));
  }
}