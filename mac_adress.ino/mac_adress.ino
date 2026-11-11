#include <WiFi.h>

void setup() {
  Serial.begin(115200);
  delay(1000);

  WiFi.begin();

  Serial.print("Receiver MAC: ");
  Serial.println(WiFi.macAddress());
}

void loop() {
}