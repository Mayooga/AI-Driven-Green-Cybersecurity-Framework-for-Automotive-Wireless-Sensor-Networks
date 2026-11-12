/*
 * sender.ino — ESP1 (Node A): ACS712 + BME280 + PIR -> AES-128-GCM -> ESP-NOW
 *
 * WIRING
 *   ACS712 OUT -> GPIO 34 (ADC1; use a divider if the module runs on 5V)
 *   BME280 SDA -> GPIO 21, SCL -> GPIO 22, VCC -> 3.3V
 *   PIR    OUT -> GPIO 27
 *
 * MODES: MODE_ALWAYS_ON (240 MHz, no sleep) | MODE_SLEEP (80 MHz, light sleep)
 *        MODE_ADAPTIVE (80 MHz, light sleep, 1 s / 10 s, PIR wakes early)
 */

#include <esp_now.h>
#include <WiFi.h>
#include <Wire.h>
#include <ctype.h>
#include <Adafruit_BME280.h>
#include <mbedtls/gcm.h>
#include <Preferences.h>
#include "esp_sleep.h"
#include "driver/gpio.h"
#include "driver/uart.h"
#include "secrets.h"          // aesKey[16]
#include "sensor_payload.h"

// ─── CONFIG ──────────────────────────────────────────────
#define MODE_ALWAYS_ON 0
#define MODE_SLEEP     1
#define MODE_ADAPTIVE  2
#define POWER_MODE     MODE_ADAPTIVE

const int ACS712_PIN = 34;
const int PIR_PIN    = 27;
const int ATTACK_NORMAL = 0;
const int ATTACK_FLOOD  = 1;
const int ATTACK_REPLAY = 2;
const int ATTACK_TAMPER = 3;
const uint32_t FLOOD_INTERVAL_MS = 1;
const uint32_t REPLAY_INTERVAL_MS = 500;
const uint32_t TAMPER_INTERVAL_MS = 500;

const uint32_t FAST_INTERVAL_MS = 1000;
const uint32_t SLOW_INTERVAL_MS = 10000;
const int      STABLE_CYCLES    = 5;

const int CUR_THR  = 30;
const int TEMP_THR = 50;
const int HUM_THR  = 300;

// ─── STATE ───────────────────────────────────────────────
mbedtls_gcm_context gcm;
Adafruit_BME280 bme;
bool bmeOk = false;

uint16_t seqCounter = 0;
uint16_t seqRemaining = 0;
const uint16_t SEQ_BLOCK_SIZE = 256;
Preferences sequenceStore;
int lastCur = 0, lastTemp = 0, lastHum = 0, lastPir = 0;
int stableCount = 0;

uint32_t statPackets = 0, statEncryptUs = 0, statAwakeMs = 0, statSleepMs = 0;
volatile bool txDone = false;
int attackMode = ATTACK_NORMAL;
const uint8_t REPLAY_BUFFER_SIZE = 8;
uint8_t replayPackets[REPLAY_BUFFER_SIZE][12 + PAYLOAD_LEN + 16];
uint8_t replayStoredPackets = 0;
uint8_t replayWriteIndex = 0;
uint8_t replayOldestIndex = 0;
uint8_t replayCursorOffset = 0;
uint8_t lastGoodPacket[12 + PAYLOAD_LEN + 16];
bool haveLastGoodPacket = false;
const uint32_t UART_COMMAND_WINDOW_MS = 10000;

bool handleSerialCommands();

void rememberReplayPacket(const uint8_t *packet) {
  memcpy(replayPackets[replayWriteIndex], packet, sizeof(lastGoodPacket));
  replayWriteIndex = (replayWriteIndex + 1) % REPLAY_BUFFER_SIZE;
  if (replayStoredPackets < REPLAY_BUFFER_SIZE) replayStoredPackets++;
}

void resetReplayCursor() {
  replayOldestIndex = (replayWriteIndex + REPLAY_BUFFER_SIZE - replayStoredPackets) % REPLAY_BUFFER_SIZE;
  replayCursorOffset = 0;
}

bool reserveSequenceBlock() {
  // Persist the end of the reserved range before using any number in it.
  // A reboot can skip unused sequence values, but will not reuse them.
  uint16_t blockStart = sequenceStore.getUShort("seqEnd", 0);
  uint16_t nextBlock = (uint16_t)(blockStart + SEQ_BLOCK_SIZE);
  if (sequenceStore.putUShort("seqEnd", nextBlock) != sizeof(uint16_t))
    return false;
  seqCounter = blockStart;
  seqRemaining = SEQ_BLOCK_SIZE;
  return true;
}

// ESP-NOW send callback signature changed in Arduino-ESP32 core 3.x.
#if ESP_ARDUINO_VERSION_MAJOR >= 3
void onSent(const wifi_tx_info_t *txInfo, esp_now_send_status_t status) {
  txDone = true;
}
#else
void onSent(const uint8_t *mac, esp_now_send_status_t status) {
  txDone = true;
}
#endif

bool radioOn() {
  WiFi.mode(WIFI_STA);
  if (esp_now_init() != ESP_OK) return false;
  if (esp_now_set_pmk(espNowPmk) != ESP_OK) {
    esp_now_deinit();
    return false;
  }
  esp_now_register_send_cb(onSent);
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, receiverMac, 6);
  peer.ifidx = WIFI_IF_STA;
  peer.channel = 0;
  peer.encrypt = true;
  memcpy(peer.lmk, espNowLmk, sizeof(peer.lmk));
  return esp_now_add_peer(&peer) == ESP_OK;
}

int readCurrentAvg() {
  uint32_t sum = 0;
  for (int i = 0; i < 16; i++) sum += analogRead(ACS712_PIN);
  return sum / 16;
}

void sleepFor(uint32_t ms) {
  Serial.flush();
  esp_now_deinit();
  WiFi.mode(WIFI_OFF);                       // radio off during sleep

  esp_sleep_enable_timer_wakeup((uint64_t)ms * 1000ULL);
  int pirNow = digitalRead(PIR_PIN);
  gpio_wakeup_enable((gpio_num_t)PIR_PIN,
                     pirNow ? GPIO_INTR_LOW_LEVEL : GPIO_INTR_HIGH_LEVEL);
  esp_sleep_enable_gpio_wakeup();
  // Let Serial Monitor wake the sender from light sleep. The wake-up text
  // itself may be lost; after the wake message, send F/R/T/N as a new line.
  uart_set_wakeup_threshold(UART_NUM_0, 3);
  esp_sleep_enable_uart_wakeup(UART_NUM_0);

  uint32_t t = millis();
  esp_light_sleep_start();
  statSleepMs += millis() - t;

  if (!radioOn()) Serial.println("# ESP-NOW re-init failed");
  if (esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_UART) {
    // The characters that wake UART from light sleep may be consumed by the
    // wake-up hardware. Stay awake so Serial Monitor has time to send the
    // actual command after this message appears.
    Serial.println("# UART awake; send F/R/T/N within 10 seconds");
    uint32_t windowStart = millis();
    while ((uint32_t)(millis() - windowStart) < UART_COMMAND_WINDOW_MS) {
      if (handleSerialCommands()) return;
      delay(10);
    }
    Serial.println("# UART command window expired; resuming normal cycle");
  }
}

bool handleSerialCommands() {
  bool commandHandled = false;
  while (Serial.available() > 0) {
    char command = (char)toupper(Serial.read());
    if (command == '?') {
      Serial.println("# CTRL READY");
      continue;
    }
    int selectedMode = -1;
    if (command == 'N') selectedMode = ATTACK_NORMAL;
    if (command == 'F') selectedMode = ATTACK_FLOOD;
    if (command == 'R') selectedMode = ATTACK_REPLAY;
    if (command == 'T') selectedMode = ATTACK_TAMPER;
    if (selectedMode < 0) continue; // ignore line endings and wake prefix

    if ((selectedMode == ATTACK_REPLAY || selectedMode == ATTACK_TAMPER) &&
        !haveLastGoodPacket) {
      Serial.println("# ERROR: let one normal packet arrive before replay/tamper");
      continue;
    }

    if (selectedMode == ATTACK_REPLAY) resetReplayCursor();
    attackMode = selectedMode;
    const char *names[] = {"NORMAL", "FLOOD", "REPLAY", "TAMPER"};
    Serial.printf("# DEMO MODE: %s\n", names[attackMode]);
    commandHandled = true;
  }
  return commandHandled;
}

void sendDemoAttack() {
  uint8_t packet[12 + PAYLOAD_LEN + 16];
  const int packetLen = sizeof(packet);

  if (attackMode == ATTACK_FLOOD) {
    // Deliberately unauthenticated test traffic; receiver should reject it.
    esp_fill_random(packet, packetLen);
    esp_now_send(receiverMac, packet, packetLen);
    delay(FLOOD_INTERVAL_MS);
    return;
  }

  if (!haveLastGoodPacket) {
    delay(50);
    return;
  }

  if (attackMode == ATTACK_TAMPER) {
    memcpy(packet, lastGoodPacket, packetLen);
    // Leave the IV intact and alter ciphertext/tag so GCM authentication fails.
    int byteToFlip = random(12, packetLen);
    packet[byteToFlip] ^= 0xFF;
    esp_now_send(receiverMac, packet, packetLen);
    delay(TAMPER_INTERVAL_MS);
    return;
  }

  // Cycle through recent authenticated normal packets. Their older sequence
  // numbers and original GCM tags remain intact, so the receiver can
  // authenticate them and reject them through its anti-replay check.
  uint8_t replayIndex = (replayOldestIndex + replayCursorOffset) % REPLAY_BUFFER_SIZE;
  memcpy(packet, replayPackets[replayIndex], packetLen);
  esp_now_send(receiverMac, packet, packetLen);
  replayCursorOffset = (replayCursorOffset + 1) % replayStoredPackets;
  delay(REPLAY_INTERVAL_MS);
}

void setup() {
  Serial.begin(115200);
  sequenceStore.begin("wsnseq", false);
  if (!reserveSequenceBlock()) {
    Serial.println("# ERROR: could not reserve persistent sequence numbers");
    while (true) delay(1000);
  }

#if POWER_MODE == MODE_ALWAYS_ON
  setCpuFrequencyMhz(240);
#else
  setCpuFrequencyMhz(80);
#endif

  pinMode(PIR_PIN, INPUT);
  analogReadResolution(12);

  Wire.begin(21, 22);
  bmeOk = bme.begin(0x76) || bme.begin(0x77);
  if (!bmeOk) Serial.println("# WARNING: BME280 not found (check wiring / address)");

  if (!radioOn()) {
    Serial.println("# ESP-NOW init failed");
    return;
  }

  mbedtls_gcm_init(&gcm);
  mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, aesKey, 128);

  Serial.printf("# Sender ready. mode=%d cpu=%luMHz payload=%dB\n",
                POWER_MODE, (unsigned long)getCpuFrequencyMhz(), PAYLOAD_LEN);
  Serial.printf("# Sender station MAC: %s\n", WiFi.macAddress().c_str());
  Serial.println("# Commands: F=flood, R=replay, T=tamper, N=normal, ?=control handshake");
}

void loop() {
  handleSerialCommands();
  if (attackMode != ATTACK_NORMAL) {
    sendDemoAttack();
    return;
  }

  uint32_t cycleStart = millis();

  // 1. READ
  SensorPayload p;
  if (seqRemaining == 0 && !reserveSequenceBlock()) {
    Serial.println("# ERROR: sequence storage failed; packet not sent");
    delay(1000);
    return;
  }
  p.seq         = seqCounter++;
  seqRemaining--;
  p.current_raw = (uint16_t)readCurrentAvg();
  p.temp_x100   = bmeOk ? (int16_t)(bme.readTemperature() * 100.0f) : 0;
  p.hum_x100    = bmeOk ? (uint16_t)(bme.readHumidity() * 100.0f)   : 0;
  p.press_x10   = bmeOk ? (uint16_t)(bme.readPressure() / 10.0f)    : 0;
  p.pir         = digitalRead(PIR_PIN) ? 1 : 0;

  // 2. DECIDE interval
  uint32_t interval = FAST_INTERVAL_MS;
#if POWER_MODE == MODE_ADAPTIVE
  bool changed = abs((int)p.current_raw - lastCur) > CUR_THR ||
                 abs((int)p.temp_x100   - lastTemp) > TEMP_THR ||
                 abs((int)p.hum_x100    - lastHum) > HUM_THR ||
                 p.pir != lastPir || p.pir == 1;
  stableCount = changed ? 0 : stableCount + 1;
  if (stableCount >= STABLE_CYCLES) interval = SLOW_INTERVAL_MS;
#endif
  lastCur = p.current_raw; lastTemp = p.temp_x100; lastHum = p.hum_x100; lastPir = p.pir;

  // 3. ENCRYPT
  uint8_t iv[12];
  esp_fill_random(iv, 12);
  uint8_t ciphertext[PAYLOAD_LEN];
  uint8_t tag[16];
  uint32_t te = micros();
  mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, PAYLOAD_LEN, iv, 12, NULL, 0,
                            (const uint8_t*)&p, ciphertext, 16, tag);
  statEncryptUs += micros() - te;

  // 4. PACK and SEND (wait for TX completion before sleeping)
  uint8_t packet[12 + PAYLOAD_LEN + 16];
  memcpy(packet, iv, 12);
  memcpy(packet + 12, ciphertext, PAYLOAD_LEN);
  memcpy(packet + 12 + PAYLOAD_LEN, tag, 16);

  // Keep one legitimate authenticated packet for controlled replay/tamper demos.
  memcpy(lastGoodPacket, packet, sizeof(packet));
  haveLastGoodPacket = true;
  rememberReplayPacket(packet);

  txDone = false;
  esp_now_send(receiverMac, packet, sizeof(packet));
  if (statPackets == 5) {   // print once, a few cycles in
    Serial.print("CAPTURED: ");
    for (int i = 0; i < sizeof(packet); i++) Serial.printf("%02X", packet[i]);
    Serial.println();
  }
  uint32_t w = millis();
  while (!txDone && millis() - w < 50) delay(1);

  statPackets++;
  Serial.printf("# seq=%u cur=%u T=%.2f H=%.2f P=%.1f pir=%u next=%lums\n",
                p.seq, p.current_raw, p.temp_x100 / 100.0, p.hum_x100 / 100.0,
                p.press_x10 / 10.0, p.pir, (unsigned long)interval);

  if (statPackets % 20 == 0) {
    Serial.printf("# STATS packets=%lu avg_encrypt_us=%lu awake_ms=%lu sleep_ms=%lu\n",
                  (unsigned long)statPackets, (unsigned long)(statEncryptUs / statPackets),
                  (unsigned long)statAwakeMs, (unsigned long)statSleepMs);
  }

  // 5. WAIT
  statAwakeMs += millis() - cycleStart;
#if POWER_MODE == MODE_ALWAYS_ON
  delay(interval);
  statAwakeMs += interval;
#else
  sleepFor(interval);
#endif
}
