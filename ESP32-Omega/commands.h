// commands.h
#ifndef COMMANDS_H
#define COMMANDS_H

int currentTarget = -1;

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
  Serial.println("  karma [on/off]    - Karma attack (probe response)");
  Serial.println("  pmkid <idx>       - Capture PMKID from AP");
  Serial.println("  pmkid stop        - Stop PMKID capture");
  Serial.println("  sae <idx>         - SAE overflow (WPA3 crash)");
  Serial.println("  sae stop          - Stop SAE overflow");
  Serial.println("");
  Serial.println("--- BLE Attacks ---");
  Serial.println("  sourapple [on/off] - SourApple iOS crash");
  Serial.println("  samspam [on/off]  - Samsung BLE spam");
  Serial.println("  spoofer [on/off]  - Apple device spoofer");
  Serial.println("  spoofer set <type> - Set spoofer type");
  Serial.println("    Types: airpods, airpodspro, airpodsmax,");
  Serial.println("           appletv, homepod, galaxy");
  Serial.println("");
  Serial.println("--- Sniffer & Detection ---");
  Serial.println("  sniffer [on/off]  - Packet sniffer");
  Serial.println("  guard [on/off]    - Deauth guard (detector)");
  Serial.println("  show creds        - Show captured credentials");
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
  Serial.println("  spoofer set airpodspro");
  Serial.println("  spoofer on");
  Serial.println("  guard on");
  Serial.println("  status");
  Serial.println("----------------------------------------");
}

#endif
