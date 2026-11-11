/*
 * decryption.ino — ESP2 (Node B / In-Vehicle Receiver)
 * 
 * ROLE: Receives encrypted ESP-NOW packets from ESP1,
 *       performs hardware-accelerated AES-128-GCM decryption,
 *       verifies the cryptographic authentication tag,
 *       and streams the result over Serial to the PC Gateway (ML IDS).
 *
 * SERIAL OUTPUT FORMAT:
 *   Success: <timestamp_ms>,<packet_length>,<sensor_value>
 *   Tamper:  <timestamp_ms>,<packet_length>,DECRYPT_FAIL
 *
 * BAUD RATE: 115200
 */

#include <esp_now.h>
#include <WiFi.h>
#include <mbedtls/gcm.h>
#include "secrets.h"

mbedtls_gcm_context gcm;

// Callback function triggered immediately when a packet arrives
void onReceive(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
  unsigned long timestamp = millis();

  // Packet format: [ IV (12 bytes) | Ciphertext (len - 28 bytes) | Tag (16 bytes) ]
  if (len < (12 + 16)) {
    Serial.print(timestamp);
    Serial.print(",");
    Serial.print(len);
    Serial.println(",DECRYPT_FAIL");
    return;
  }

  uint8_t iv[12];
  memcpy(iv, data, 12);

  int ctLen = len - 12 - 16;
  const uint8_t *ciphertext = data + 12;
  const uint8_t *tag = data + 12 + ctLen;

  uint8_t plaintext[32];

  // Decrypt and verify tag simultaneously
  int ok = mbedtls_gcm_auth_decrypt(
    &gcm, ctLen,
    iv, 12,
    NULL, 0,
    tag, 16,
    ciphertext,
    plaintext
  );

  // If ok != 0, tag mismatch! Packet was altered or corrupted
  if (ok != 0) {
    Serial.print(timestamp);
    Serial.print(",");
    Serial.print(len);
    Serial.println(",DECRYPT_FAIL");
    return;
  }

  // Decryption successful
  plaintext[ctLen] = '\0';
  Serial.print(timestamp);
  Serial.print(",");
  Serial.print(len);
  Serial.print(",");
  Serial.println((char*)plaintext);
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);

  // Initialize ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW Init Failed");
    return;
  }

  // Register receive callback
  esp_now_register_recv_cb(onReceive);

  // Initialize AES-128-GCM cipher
  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);

  Serial.println("Receiver Ready. Listening for encrypted packets...");
}

void loop() {
  // Free loop — onReceive handles incoming packets asynchronously
}
