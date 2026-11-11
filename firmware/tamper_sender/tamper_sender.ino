/*
 * tamper_sender.ino — ESP1 (Node A), TAMPER ATTACK VARIANT
 *
 * ROLE: Same as sender.ino (read ACS712 + AES-128-GCM encrypt + send),
 *       but deliberately corrupts one byte of the CIPHERTEXT before
 *       transmission, so the receiver's GCM tag verification fails.
 *
 * WHY THIS VERSION: your original tamper firmware flipped a byte inside
 * the IV (packet[5], which falls in bytes 0-11). That still causes
 * DECRYPT_FAIL (GCM ties the tag to both IV and ciphertext), but your
 * paper's Table V explicitly states the attack mechanism as "Bit-flip on
 * ciphertext byte (XOR 0xFF)" -- so the firmware needs to match that.
 * This version flips packet[12], which is always the FIRST CIPHERTEXT
 * byte (since the IV is always exactly the first 12 bytes), regardless
 * of how long the sensor-value string is.
 *
 * SERIAL OUTPUT: identical format to sender.ino, so your existing
 * receiver (decryption.ino) and CSV logging pipeline need no changes --
 * you'll just see DECRYPT_FAIL / label 'tamper' rows on the receiver end.
 *
 * WIRING:
 *   ACS712 OUT -> GPIO 34
 *   ACS712 VCC -> 5V
 *   ACS712 GND -> GND
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

  Serial.print("ESP1 (Tamper Sender) MAC: ");
  Serial.println(WiFi.macAddress());

  if (esp_now_init() != ESP_OK) {
    Serial.println("ESP-NOW init failed!");
    return;
  }

  esp_now_peer_info_t peerInfo = {};
  memcpy(peerInfo.peer_addr, receiverMac, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;
  esp_now_add_peer(&peerInfo);

  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);

  Serial.println("Tamper sender ready. Corrupting ciphertext byte before each send...\n");
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

  // 6. TAMPER: flip the first ciphertext byte (packet[12] is always the
  //    start of ciphertext, since IV always occupies bytes 0-11).
  //    This matches Table V: "Bit-flip on ciphertext byte (XOR 0xFF)".
  packet[5] = packet[5] ^ 0xFF;

  // 7. SEND via ESP-NOW (tag will fail verification at the receiver)
  esp_now_send(receiverMac, packet, 12 + len + 16);

  Serial.print("Sent (ciphertext-corrupted) sensor value: ");
  Serial.println(sensorValue);

  delay(SEND_INTERVAL_MS);
}
