/*
 * sender.ino — ESP1 (Node A)
 * 
 * ROLE: Read ACS712 current sensor + Encrypt + Send
 * This node ONLY reads and sends. No detection logic here.
 * The receiver (ESP2) handles all security checks.
 *
 * WIRING:
 *   ACS712 OUT → GPIO 34
 *   ACS712 VCC → 5V
 *   ACS712 GND → GND
 */

#include <esp_now.h>
#include <WiFi.h>
#include <mbedtls/gcm.h>
#include "secrets.h"

// ─── CONFIG ───────────────────────────────────────────
const int ACS712_PIN = 34;
const int SEND_INTERVAL_MS = 1000;  

mbedtls_gcm_context gcm;

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);

  Serial.print("ESP1 (Sender) MAC: ");
  Serial.println(WiFi.macAddress());

  // Initialize ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed!");
    return;
  }

  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, receiverMac, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;
  esp_now_add_peer(&peerInfo);

  // Initialize AES-GCM
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);

  Serial.println("Sender ready. Reading sensor + encrypting + sending...\n");
}

void loop() {
  // 1. READ sensor
  int sensorValue = analogRead(ACS712_PIN);

  // 2. CONVERT to string
  char msg[16];
  sprintf(msg, "%d", sensorValue);
  int len = strlen(msg);

  // 3. GENERATE fresh random IV for this packet
  uint8_t iv[12];
  esp_fill_random(iv, 12);

  // 4. ENCRYPT with AES-128-GCM
  uint8_t ciphertext[32];
  uint8_t tag[16];
  mbedtls_gcm_crypt_and_tag(
    &gcm, MBEDTLS_GCM_ENCRYPT,
    len, iv, 12, NULL, 0,
    (uint8_t*)msg, ciphertext, 16, tag
  );

  // 5. PACK: [IV (12 bytes) | Ciphertext (len bytes) | Tag (16 bytes)]
  uint8_t packet[12 + 32 + 16];
  memcpy(packet, iv, 12);
  memcpy(packet + 12, ciphertext, len);
  memcpy(packet + 12 + len, tag, 16);

  // 6. SEND via ESP-NOW
  esp_now_send(receiverMac, packet, 12 + len + 16);

  Serial.print("Sent encrypted: ");
  Serial.println(sensorValue);

  delay(SEND_INTERVAL_MS);
}
