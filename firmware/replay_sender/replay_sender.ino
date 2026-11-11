/*
 * replay_sender.ino — ESP1 (Node A), REPLAY ATTACK VARIANT (intermittent)
 *
 * ROLE: Sends genuine encrypted readings most of the time, but every
 *       REPLAY_EVERY_N-th packet re-transmits a previously captured
 *       packet instead of a fresh one.
 *
 * WHY CHANGED FROM YOUR ORIGINAL VERSION:
 *   - Old version replayed the SAME single packet forever after a 2-packet
 *     warm-up, giving repeat_rate_5 a flat step (0 -> 1) that's trivially
 *     easy for the classifier to learn and not representative of a real
 *     attacker mixing replayed + live traffic.
 *   - This version keeps refreshing "oldPacket" with the last genuine
 *     packet sent, and only replays it occasionally (default: every 4th
 *     packet), so repeat_rate_5 shows a realistic gradient instead of a
 *     flat 0/1 signal.
 *   - REPLAY_START_AFTER lets you skip labeling the very first few
 *     legitimate warm-up packets as "replay" at the CSV stage (see note
 *     at bottom) -- this firmware still sends them, just flagged in
 *     Serial output so you can strip them during logging.
 *
 * TUNE REPLAY_EVERY_N to generate multiple intensity variants for your
 * paper's robustness analysis, e.g. run this firmware three times with
 * REPLAY_EVERY_N = 2, 4, 8 to get high/medium/low intensity replay sets.
 */

#include <esp_now.h>
#include <WiFi.h>
#include <mbedtls/gcm.h>
#include "secrets.h"

const int ACS712_PIN = 34;

const int SEND_INTERVAL_MS   = 1000;
const int REPLAY_START_AFTER = 2;   // don't replay until we've captured at least 1 real packet
const int REPLAY_EVERY_N     = 4;   // replay 1 out of every N packets (tune per session)

mbedtls_gcm_context gcm;

static uint8_t oldPacket[64];
static int oldLen = 0;
static int counter = 0;

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);

  Serial.print("ESP1 (Replay Sender) MAC: ");
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

  Serial.println("Intermittent replay sender ready.\n");
}

void loop() {
  counter++;

  bool canReplay   = (counter > REPLAY_START_AFTER) && (oldLen > 0);
  bool doReplay    = canReplay && (counter % REPLAY_EVERY_N == 0);
  bool isWarmup    = (counter <= REPLAY_START_AFTER);

  if (doReplay) {
    esp_now_send(receiverMac, oldPacket, oldLen);
    Serial.println("Replayed old packet (ATTACK)");
    delay(SEND_INTERVAL_MS);
    return;
  }

  // Genuine fresh reading (also used to refresh oldPacket for future replays)
  int sensorValue = analogRead(ACS712_PIN);

  char msg[16];
  sprintf(msg, "%d", sensorValue);
  int len = strlen(msg);

  uint8_t iv[12];
  esp_fill_random(iv, 12);

  uint8_t ciphertext[32];
  uint8_t tag[16];
  mbedtls_gcm_crypt_and_tag(
    &gcm, MBEDTLS_GCM_ENCRYPT,
    len, iv, 12, NULL, 0,
    (uint8_t*)msg, ciphertext, 16, tag
  );

  uint8_t packet[12 + 32 + 16];
  memcpy(packet, iv, 12);
  memcpy(packet + 12, ciphertext, len);
  memcpy(packet + 12 + len, tag, 16);

  // Save this genuine packet so a future iteration can replay it
  memcpy(oldPacket, packet, 12 + len + 16);
  oldLen = 12 + len + 16;

  esp_now_send(receiverMac, packet, 12 + len + 16);

  if (isWarmup) {
    Serial.print("WARMUP (label as normal, not replay): ");
  } else {
    Serial.print("Sent genuine (interleaved) value: ");
  }
  Serial.println(sensorValue);

  delay(SEND_INTERVAL_MS);
}
