#!/usr/bin/env python3
"""
Interactive front-end for the ESP32 handshake-capture sketch.

- Prints everything the ESP32 sends over serial (including the numbered
  network list) so you can see it live.
- Forwards whatever you type + Enter back to the ESP32 (e.g. the network
  number to target, or 'r' to rescan).
- Any "EAPOL:<hex>" line is decoded and written into a real .pcap file
  (LINKTYPE_IEEE802_11) for offline analysis with hashcat / hcxtools.

Usage:
    python3 capture_handshake.py [/dev/ttyUSB0] [baud] [output.pcap]

With no arguments, defaults to COM30 @ 115200, writing to
captures/handshake.pcap next to this script.

Press Ctrl+C to stop; the .pcap written so far stays valid.
"""
import os
import sys
import struct
import threading
import time
import serial

CAPTURES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures")

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_IEEE802_11 = 105

def write_pcap_header(f):
    f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 262144, LINKTYPE_IEEE802_11))

def write_pcap_packet(f, data):
    f.write(struct.pack("<IIII", 0, 0, len(data), len(data)))
    f.write(data)

def reader_thread(ser, f, counter):
    while True:
        try:
            line = ser.readline().decode(errors="replace").rstrip("\r\n")
        except serial.SerialException:
            break
        if not line:
            continue
        if line.startswith("EAPOL:") or line.startswith("BEACON:"):
            tag, hexstr = line.split(":", 1)
            try:
                data = bytes.fromhex(hexstr)
            except ValueError:
                continue
            write_pcap_packet(f, data)
            f.flush()
            if tag == "EAPOL":
                counter[0] += 1
                print(f"[+] wrote EAPOL frame #{counter[0]} ({len(data)} bytes)")
            else:
                print(f"[+] wrote BEACON frame ({len(data)} bytes) - gives hcxpcapngtool the SSID")
        else:
            print(line)

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else "COM30"
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else 115200
    outpath = sys.argv[3] if len(sys.argv) > 3 else os.path.join(CAPTURES_DIR, "handshake.pcap")
    os.makedirs(os.path.dirname(outpath) or ".", exist_ok=True)

    ser = serial.Serial(port, baud, timeout=1)
    # Releasing DTR/RTS avoids leaving the board held in reset/bootloader
    # mode by the CP2102's auto-reset wiring.
    ser.dtr = False
    ser.rts = False
    time.sleep(3)

    counter = [0]
    with open(outpath, "wb") as f:
        write_pcap_header(f)
        f.flush()
        print(f"Connected to {port} @ {baud} baud, writing EAPOL frames to {outpath}")
        print("Type a network number + Enter when the list appears. Ctrl+C to stop.\n")

        t = threading.Thread(target=reader_thread, args=(ser, f, counter), daemon=True)
        t.start()

        try:
            while True:
                user_input = input()
                ser.write((user_input + "\n").encode())
        except (KeyboardInterrupt, EOFError):
            pass

    print(f"\nDone. Captured {counter[0]} EAPOL frames into {outpath}")
    if counter[0] < 4:
        print("Warning: fewer than 4 EAPOL frames captured - handshake may be incomplete.")
        print("Try again while a client is actively connecting to the target network.")

if __name__ == "__main__":
    main()
