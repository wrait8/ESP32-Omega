// ESP32-Omega Unified Toolkit
#include <WiFi.h>
#include <esp_wifi.h>
#include <esp_bt.h>
#include <BLEDevice.h>
#include <BLEAdvertising.h>
#include <BLEUtils.h>
#include <esp_bt_main.h>
#include <esp_gap_ble_api.h>
#include <SPIFFS.h>
#include <DNSServer.h>
#include <WebServer.h>

// ============= CONFIGURATION =============
#define VERSION "v2.0"
#define SERIAL_BAUD 115200
#define MAX_NETWORKS 50
#define DEAUTH_WINDOW 5  // seconds

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
  bool spooferRunning;
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
};

NetworkInfo networks[MAX_NETWORKS];
int networkCount = 0;

// ============= INCLUDE ALL MODULES =============
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
#include "spoofer.h"
#include "commands.h"

// ============= COMMAND PARSER =============
void processCommand(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;
  
  // Split command and args
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
    if (args == "on") {
      startKarmaAttack();
      state.karmaRunning = true;
      Serial.println("Karma attack started");
    } else if (args == "off") {
      stopKarmaAttack();
      state.karmaRunning = false;
      Serial.println("Karma attack stopped");
    } else {
      Serial.println("Usage: karma [on/off]");
    }
  }
  else if (command == "pmkid") {
    if (args == "stop") {
      stopPMKIDCapture();
      state.pmkidCaptureRunning = false;
      Serial.println("PMKID capture stopped");
    } else if (args.length() > 0) {
      int idx = args.toInt();
      if (idx >= 0 && idx < networkCount) {
        startPMKIDCapture(idx);
        state.pmkidCaptureRunning = true;
        Serial.printf("PMKID capture started on %s\n", networks[idx].ssid.c_str());
      } else {
        Serial.println("Invalid network index");
      }
    } else {
      Serial.println("Usage: pmkid <idx> | stop");
    }
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
  else if (command == "spoofer") {
    if (args == "on") {
      startSpoofer();
      state.spooferRunning = true;
      Serial.println("Spoofer started");
    } else if (args == "off") {
      stopSpoofer();
      state.spooferRunning = false;
      Serial.println("Spoofer stopped");
    } else if (args.length() > 0 && args.startsWith("set")) {
      // Handle spoofer set commands
      handleSpooferCommand(args);
    } else {
      Serial.println("Usage: spoofer [on/off | set <type>]");
      Serial.println("Types: airpods, airpodspro, airpodsmax, appletv, homepod, galaxy");
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
    } else {
      Serial.println("Usage: guard [on/off]");
    }
  }
  else if (command == "show") {
    if (args == "creds" || args == "credentials") {
      showCredentials();
    } else {
      Serial.println("Usage: show creds");
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
    
    wifi_auth_mode_t auth = WiFi.encryptionType(i);
    networks[i].isWPA2 = (auth == WIFI_AUTH_WPA2_PSK || auth == WIFI_AUTH_WPA2_ENTERPRISE);
    networks[i].isWPA3 = (auth == WIFI_AUTH_WPA3_PSK || auth == WIFI_AUTH_WPA2_WPA3_PSK);
    networks[i].isOpen = (auth == WIFI_AUTH_OPEN);
    
    String type = networks[i].isWPA3 ? "WPA3" : (networks[i].isWPA2 ? "WPA2" : (networks[i].isOpen ? "OPEN" : "WPA"));
    
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
  scanNetworks(); // Re-scan to refresh
}

void selectNetwork(int idx) {
  if (idx >= 0 && idx < networkCount) {
    currentTarget = idx;
    Serial.printf("Selected: %s\n", networks[idx].ssid.c_str());
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
  Serial.printf("Spoofer: %s\n", state.spooferRunning ? "RUNNING" : "STOPPED");
}

void showCredentials() {
  Serial.println("\n=== Captured Credentials ===");
  // This would read from SPIFFS
  // For now, just show a message
  Serial.println("No credentials captured yet.");
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

// ============= SERIAL CLI LOOP =============
void serialCLI() {
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim();
    if (cmd.length() > 0) {
      processCommand(cmd);
    }
  }
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
    runKarma();
  }
  if (state.pmkidCaptureRunning) {
    runPMKIDCapture();
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
  if (state.spooferRunning) {
    runSpoofer();
  }
  
  // Print prompt if serial CLI is active
  static unsigned long lastPrompt = 0;
  if (millis() - lastPrompt > 5000) {
    lastPrompt = millis();
    // Uncomment to show prompt periodically
    // Serial.print("> ");
  }
  
  delay(10);
}
