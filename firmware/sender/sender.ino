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
#include <Adafruit_BME280.h>
#include <mbedtls/gcm.h>
#include "esp_sleep.h"
#include "driver/gpio.h"
#include "secrets.h"          // aesKey[16]
#include "sensor_payload.h"

uint8_t receiverMac[] = { 0x8C, 0x94, 0xDF, 0x6B, 0xF1, 0x34 };

// ─── CONFIG ──────────────────────────────────────────────
#define MODE_ALWAYS_ON 0
#define MODE_SLEEP     1
#define MODE_ADAPTIVE  2
#define POWER_MODE     MODE_ADAPTIVE

const int ACS712_PIN = 34;
const int PIR_PIN    = 27;

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

RTC_DATA_ATTR uint16_t seqCounter = 0;
int lastCur = 0, lastTemp = 0, lastHum = 0, lastPir = 0;
int stableCount = 0;

uint32_t statPackets = 0, statEncryptUs = 0, statAwakeMs = 0, statSleepMs = 0;
volatile bool txDone = false;

// Send callback (core 3.0.x signature)
void onSent(const uint8_t *mac, esp_now_send_status_t status) { txDone = true; }

bool radioOn() {
  WiFi.mode(WIFI_STA);
  if (esp_now_init() != ESP_OK) return false;
  esp_now_register_send_cb(onSent);
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, receiverMac, 6);
  peer.channel = 0;
  peer.encrypt = false;
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

  uint32_t t = millis();
  esp_light_sleep_start();
  statSleepMs += millis() - t;

  if (!radioOn()) Serial.println("# ESP-NOW re-init failed");
}

void setup() {
  Serial.begin(115200);

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
}

void loop() {
  uint32_t cycleStart = millis();

  // 1. READ
  SensorPayload p;
  p.seq         = seqCounter++;
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

  txDone = false;
  esp_now_send(receiverMac, packet, sizeof(packet));
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