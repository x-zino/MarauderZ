#!/usr/bin/env python3
"""
List the BSSID/ESSID of every hash entry in a hashcat .hc22000 file, so you
can pick the right line before isolating your target network.

Usage:
    python3 list_hc22000.py [path_of_file]

If no path is given on the command line, HC22000_PATH below is used -
edit it to point at your own file.
"""
import os
import sys

HC22000_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "captures", "handshake.hc22000")

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else HC22000_PATH

    with open(path) as f:
        for i, line in enumerate(l.strip() for l in f if l.strip()):
            parts = line.split("*")
            bssid = parts[3]
            essid = bytes.fromhex(parts[5]).decode(errors="replace")
            print(f"line {i}: BSSID={bssid}  ESSID={essid}")

if __name__ == "__main__":
    main()
