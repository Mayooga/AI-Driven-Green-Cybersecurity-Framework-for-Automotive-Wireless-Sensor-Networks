#pragma once
// Shared by sender, flood_sender, replay_sender, tamper_sender and decryption.
// Keep an IDENTICAL copy of this file in every sketch folder.
#include <stdint.h>

#pragma pack(push, 1)
struct SensorPayload {
  uint16_t seq;          // packet counter (inside the encrypted payload -> exact replay detection)
  uint16_t current_raw;  // ACS712 ADC reading (0-4095)
  int16_t  temp_x100;    // BME280 temperature, degC x 100
  uint16_t hum_x100;     // BME280 humidity, %RH x 100
  uint16_t press_x10;    // BME280 pressure, hPa x 10
  uint8_t  pir;          // PIR motion, 0 or 1
};
#pragma pack(pop)

static const int PAYLOAD_LEN = sizeof(SensorPayload);   // 11 bytes
// Packet on air: [ IV 12 | ciphertext 11 | GCM tag 16 ] = 39 bytes (constant)
