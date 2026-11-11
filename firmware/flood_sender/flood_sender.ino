#include <esp_now.h>
#include <WiFi.h>
#include <mbedtls/gcm.h>
#include "secrets.h"

const int ACS712_PIN = 34;
mbedtls_gcm_context gcm;

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  esp_now_init();
  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, receiverMac, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;
  esp_now_add_peer(&peerInfo);
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);
}

void loop() {
  int sensorValue = analogRead(ACS712_PIN);

  char msg[16];
  sprintf(msg, "%d", sensorValue);
  int len = strlen(msg);

  uint8_t iv[12];
  esp_fill_random(iv, 12);
  uint8_t ciphertext[32];
  uint8_t tag[16];
  mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, len, iv, 12, NULL, 0, (uint8_t*)msg, ciphertext, 16, tag);

  uint8_t packet[12 + 32 + 16];
  memcpy(packet, iv, 12);
  memcpy(packet + 12, ciphertext, len);
  memcpy(packet + 12 + len, tag, 16);

  esp_now_send(receiverMac, packet, 12 + len + 16);
  Serial.print("Sent encrypted sensor value: ");
  Serial.println(sensorValue);
  delay(10);  // ⚡ High-speed flood matching training data (1-4ms gaps)
}
