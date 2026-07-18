// sniffer.h
#ifndef SNIFFER_H
#define SNIFFER_H

#include <esp_wifi.h>
#include <esp_wifi_types.h>

bool snifferActive = false;
int currentChannel = 1;

void startSniffer() {
  snifferActive = true;
  currentChannel = 1;
  
  esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb([](void* buff, wifi_promiscuous_pkt_type_t type) {
    if (!snifferActive) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buff;
    uint8_t* payload = pkt->payload;
    
    char typeStr[8];
    switch(type) {
      case WIFI_PKT_MGMT: sprintf(typeStr, "MGMT"); break;
      case WIFI_PKT_DATA: sprintf(typeStr, "DATA"); break;
      default: sprintf(typeStr, "MISC"); break;
    }
    
    char addr1[18], addr2[18], addr3[18];
    snprintf(addr1, sizeof(addr1), "%02X:%02X:%02X:%02X:%02X:%02X",
      payload[4], payload[5], payload[6], payload[7], payload[8], payload[9]);
    snprintf(addr2, sizeof(addr2), "%02X:%02X:%02X:%02X:%02X:%02X",
      payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]);
    snprintf(addr3, sizeof(addr3), "%02X:%02X:%02X:%02X:%02X:%02X",
      payload[16], payload[17], payload[18], payload[19], payload[20], payload[21]);
    
    Serial.printf("[%s] CH:%02d RSSI:%3d | A1:%s | A2:%s\n",
      typeStr, pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi, addr1, addr2);
  });
  
  Serial.println("Sniffer started on channel 1");
}

void stopSniffer() {
  snifferActive = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  Serial.println("Sniffer stopped");
}

void runSniffer() {
  if (!snifferActive) return;
  
  static unsigned long lastHop = 0;
  if (millis() - lastHop > 500) {
    lastHop = millis();
    currentChannel = (currentChannel % 13) + 1;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
  }
  
  delay(10);
}

#endif
