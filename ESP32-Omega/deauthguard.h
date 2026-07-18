// deauthguard.h
#ifndef DEAUTHGUARD_H
#define DEAUTHGUARD_H

#include <esp_wifi.h>
#include <map>

bool deauthGuardActive = false;
std::map<String, int> deauthCount;
std::map<String, unsigned long> deauthTime;
std::map<String, int> deauthAttacks;
int deauthThreshold = 10;

void startDeauthGuard() {
  deauthGuardActive = true;
  deauthCount.clear();
  deauthTime.clear();
  deauthAttacks.clear();
  
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb([](void* buf, wifi_promiscuous_pkt_type_t type) {
    if (!deauthGuardActive) return;
    if (type != WIFI_PKT_MGMT) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* payload = pkt->payload;
    
    if ((payload[0] & 0x0C) != 0x0C) return;
    
    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
      payload[10], payload[11], payload[12], payload[13], payload[14], payload[15]);
    
    String source(mac);
    unsigned long now = millis();
    
    if (deauthCount.find(source) == deauthCount.end()) {
      deauthCount[source] = 1;
      deauthTime[source] = now;
    } else {
      deauthCount[source]++;
      if (deauthCount[source] > deauthThreshold && 
          (now - deauthTime[source]) < 1000) {
        Serial.printf("DEAUTH GUARD: Attack detected from %s (%d packets)\n", 
          source.c_str(), deauthCount[source]);
        
        if (deauthAttacks.find(source) == deauthAttacks.end()) {
          deauthAttacks[source] = 1;
        } else {
          deauthAttacks[source]++;
        }
        
        deauthCount[source] = 0;
        deauthTime[source] = now;
      }
      if ((now - deauthTime[source]) > 1000) {
        deauthCount[source] = 0;
        deauthTime[source] = now;
      }
    }
  });
  
  Serial.println("Deauth guard started");
}

void stopDeauthGuard() {
  deauthGuardActive = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  Serial.println("Deauth guard stopped");
}

void printDeauthGuardStatus() {
  Serial.printf("\n=== Deauth Guard Status ===\n");
  Serial.printf("Active: %s\n", deauthGuardActive ? "YES" : "NO");
  Serial.printf("Threshold: %d packets/sec\n", deauthThreshold);
  Serial.printf("Active attackers: %d\n", deauthAttacks.size());
  
  if (deauthAttacks.size() > 0) {
    Serial.println("\nDetected attacks:");
    for (auto& attack : deauthAttacks) {
      Serial.printf("  %s: %d attacks\n", attack.first.c_str(), attack.second);
    }
  }
}

void runDeauthGuard() {
  delay(10);
}

#endif
