// beaconspam.h
#ifndef BEACONSPAM_H
#define BEACONSPAM_H

#include <esp_wifi.h>

bool beaconSpamActive = false;
int beaconCount = 0;
int maxBeacons = 100;

uint8_t beaconPacket[128] = {
  0x80, 0x00, 0x00, 0x00,  // Frame control
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // Broadcast
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // SRC
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // BSSID
  0xC0, 0x6C,  // Sequence
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Timestamp
  0x64, 0x00,  // Beacon interval
  0x01, 0x04,  // Capability
  0x00  // SSID tag (length follows)
};

const char* ssidChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const char* ssidPrefix = "ESP_";

void startBeaconSpam(int count) {
  beaconSpamActive = true;
  maxBeacons = count;
  beaconCount = 0;
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_max_tx_power(82);
  Serial.printf("Beacon spam started (target: %d packets)\n", count);
}

void stopBeaconSpam() {
  beaconSpamActive = false;
  esp_wifi_set_promiscuous(false);
  Serial.println("Beacon spam stopped");
}

void runBeaconSpam() {
  if (!beaconSpamActive || beaconCount >= maxBeacons) {
    if (beaconCount >= maxBeacons) {
      stopBeaconSpam();
      Serial.printf("Beacon spam complete (%d packets sent)\n", beaconCount);
    }
    return;
  }
  
  // Random channel
  int channel = random(1, 13);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  
  // Randomize MAC
  for (int i = 0; i < 6; i++) {
    uint8_t b = random(256);
    beaconPacket[10 + i] = b;  // SRC
    beaconPacket[16 + i] = b;  // BSSID
  }
  
  // Random SSID (6 chars with prefix)
  beaconPacket[37] = 6;  // SSID length
  for (int i = 0; i < 6; i++) {
    beaconPacket[38 + i] = ssidChars[random(36)];
  }
  
  // Channel in supported rates
  beaconPacket[56] = channel;
  
  // Send 3 times for reliability
  for (int i = 0; i < 3; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, beaconPacket, sizeof(beaconPacket), false);
  }
  
  beaconCount++;
  delay(1);
}

#endif
