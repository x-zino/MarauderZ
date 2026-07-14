#!/usr/bin/env python3
"""
GUI front-end for MarauderZ for Windows PC — an ESP32 WiFi password
strength audit toolkit built for Windows.


Requires: Python 3 stdlib (tkinter) + pyserial (same dependency the CLI
capture script needs).

by - zino
"""
import os
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, ttk

try:
    import serial
    import serial.tools.list_ports
except ImportError:
    serial = None

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_IEEE802_11 = 105

# When frozen by PyInstaller, __file__ resolves inside the onefile temp
# extraction dir (a fresh path every run), not the folder the .exe lives
# in - so captures/downloads/photos must anchor on sys.executable instead.
if getattr(sys, "frozen", False):
    PROJECT_DIR = Path(sys.executable).resolve().parent
else:
    PROJECT_DIR = Path(__file__).resolve().parent
FIRMWARE_DIR = PROJECT_DIR / "firmware"
DOWNLOADS_DIR = PROJECT_DIR / "downloads"   # third-party downloads: hashcat, rockyou.txt
CAPTURES_DIR = PROJECT_DIR / "captures"     # your own run output: pcap, hc22000, cracked.txt
PHOTOS_DIR = PROJECT_DIR / "photos"

# These hold your own capture data / downloaded tools, not source - see
# .gitignore. Created here so the GUI's default save/open paths always
# resolve even on a freshly cloned repo.
CAPTURES_DIR.mkdir(exist_ok=True)
DOWNLOADS_DIR.mkdir(exist_ok=True)


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def write_pcap_header(f):
    f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 262144, LINKTYPE_IEEE802_11))


def write_pcap_packet(f, data):
    f.write(struct.pack("<IIII", 0, 0, len(data), len(data)))
    f.write(data)


def win_path_to_wsl(win_path: str) -> str:
    p = Path(win_path).resolve()
    drive = p.drive.rstrip(":").lower()
    rest = str(p)[len(p.drive) + 1:].replace("\\", "/")
    return f"/mnt/{drive}/{rest}"


def parse_hc22000_line(line: str):
    """Returns (bssid, essid, essid_hex). essid_hex is the raw hex field
    from the line itself (not re-derived from the decoded essid), so
    isolating by it later is an exact match even for non-UTF-8 SSIDs."""
    parts = line.strip().split("*")
    bssid = parts[3]
    essid_hex = parts[5]
    essid = bytes.fromhex(essid_hex).decode(errors="replace")
    return bssid, essid, essid_hex


def find_arduino_cli() -> str:
    """Resolves arduino-cli the same way the hashcat.exe fix does: a bare
    name is resolved against *this GUI process's own* PATH, which can be
    stale (e.g. arduino-cli was installed after this Python process/its
    parent shell started) even though a brand new process would find it
    fine. Falls back to the standard winget install location, then to the
    bare name as a last resort."""
    found = shutil.which("arduino-cli")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Arduino CLI\arduino-cli.exe",
        r"C:\Program Files (x86)\Arduino CLI\arduino-cli.exe",
    ):
        if os.path.isfile(candidate):
            return candidate
    return "arduino-cli"


class LogPanel(ttk.Frame):
    """A scrolled text box that worker threads can safely append to
    via a queue, drained on the Tk main loop with .after()."""

    def __init__(self, master):
        super().__init__(master)
        self.text = scrolledtext.ScrolledText(self, height=14, state="disabled",
                                               background="#111", foreground="#0f0",
                                               font=("Consolas", 9))
        self.text.pack(fill="both", expand=True)
        self._queue: "queue.Queue[str]" = queue.Queue()
        self.after(80, self._drain)

    def log(self, msg: str):
        self._queue.put(msg)

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", tk.END)
        self.text.configure(state="disabled")

    def _drain(self):
        drained = False
        while True:
            try:
                msg = self._queue.get_nowait()
            except queue.Empty:
                break
            drained = True
            self.text.configure(state="normal")
            self.text.insert(tk.END, msg.rstrip("\n") + "\n")
            self.text.configure(state="disabled")
        if drained:
            self.text.see(tk.END)
        self.after(80, self._drain)


def run_streaming(cmd, log: LogPanel, cwd=None, on_done=None, shell=False):
    """Runs cmd in a background thread, streaming stdout/stderr into log."""

    def worker():
        log.log(f"$ {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd, cwd=cwd, shell=shell,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            for line in proc.stdout:
                log.log(line)
            proc.wait()
            log.log(f"[exit code {proc.returncode}]")
        except Exception as e:
            log.log(f"[error] {e}")
        finally:
            if on_done:
                on_done()

    threading.Thread(target=worker, daemon=True).start()


def browse_file(entry: tk.Entry, save=False, filetypes=(("All files", "*.*"),), initialfile="",
                 initialdir=None):
    if save:
        path = filedialog.asksaveasfilename(filetypes=filetypes, initialfile=initialfile,
                                             initialdir=initialdir)
    else:
        path = filedialog.askopenfilename(filetypes=filetypes, initialdir=initialdir)
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)


def browse_dir(entry: tk.Entry):
    path = filedialog.askdirectory()
    if path:
        entry.delete(0, tk.END)
        entry.insert(0, path)


# --------------------------------------------------------------------------
# Tab 1: Flash
# --------------------------------------------------------------------------

class FlashTab(ttk.Frame):
    def __init__(self, master, port_var: tk.StringVar):
        super().__init__(master, padding=10)
        self.port_var = port_var

        ttk.Label(self, text="arduino-cli.exe (auto-detected; browse if this is wrong):").grid(
            row=0, column=0, sticky="w")
        self.cli_entry = ttk.Entry(self, width=60)
        self.cli_entry.insert(0, find_arduino_cli())
        self.cli_entry.grid(row=1, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...",
                   command=lambda: browse_file(self.cli_entry,
                                                filetypes=(("arduino-cli.exe", "arduino-cli.exe"), ("All files", "*.*")))
                   ).grid(row=1, column=1)

        ttk.Label(self, text="Sketch folder (contains the .ino file):").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.sketch_entry = ttk.Entry(self, width=60)
        self.sketch_entry.insert(0, str(FIRMWARE_DIR / "MarauderZ_sniffer"))
        self.sketch_entry.grid(row=3, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...", command=lambda: browse_dir(self.sketch_entry)).grid(row=3, column=1)

        ttk.Label(self, text="FQBN:").grid(row=4, column=0, sticky="w", pady=(10, 0))
        self.fqbn_entry = ttk.Entry(self, width=30)
        self.fqbn_entry.insert(0, "esp32:esp32:esp32")
        self.fqbn_entry.grid(row=5, column=0, sticky="w")

        port_row = ttk.Frame(self)
        port_row.grid(row=6, column=0, columnspan=2, sticky="w", pady=(10, 0))
        ttk.Label(port_row, text="COM port:").pack(side="left")
        self.port_combo = ttk.Combobox(port_row, textvariable=self.port_var, width=12, values=self._list_ports())
        self.port_combo.pack(side="left", padx=5)
        ttk.Button(port_row, text="Refresh", command=self.refresh_ports).pack(side="left", padx=5)
        ttk.Label(self, text="(shared with the Capture tab - set it once, use it everywhere)",
                  foreground="#888").grid(row=7, column=0, columnspan=2, sticky="w")

        btns = ttk.Frame(self)
        btns.grid(row=8, column=0, columnspan=2, pady=10, sticky="w")
        ttk.Button(btns, text="Install ESP32 core", command=self.install_core).pack(side="left", padx=(0, 5))
        ttk.Button(btns, text="Compile", command=self.compile).pack(side="left", padx=5)
        ttk.Button(btns, text="Upload", command=self.upload).pack(side="left", padx=5)
        ttk.Button(btns, text="Compile + Upload", command=self.compile_and_upload).pack(side="left", padx=5)

        self.log = LogPanel(self)
        self.log.grid(row=9, column=0, columnspan=2, sticky="nsew")
        self.rowconfigure(9, weight=1)
        self.columnconfigure(0, weight=1)

    def _list_ports(self):
        if serial is None:
            return []
        return [p.device for p in serial.tools.list_ports.comports()]

    def refresh_ports(self):
        self.port_combo["values"] = self._list_ports()

    def _cli(self):
        """Always the full path/typed value from the entry, never a bare
        'arduino-cli' resolved implicitly - see find_arduino_cli()/the
        hashcat.exe fix for why a bare name is unreliable here."""
        cli = self.cli_entry.get().strip()
        if not cli:
            messagebox.showerror("arduino-cli not set", "Fill in the arduino-cli.exe path above (or Browse to it).")
            return None
        return cli

    def install_core(self):
        cli = self._cli()
        if cli is None:
            return
        run_streaming([cli, "core", "install", "esp32:esp32"], self.log)

    def compile(self):
        cli = self._cli()
        if cli is None:
            return
        run_streaming([cli, "compile", "--fqbn", self.fqbn_entry.get(), "."],
                       self.log, cwd=self.sketch_entry.get())

    def upload(self):
        cli = self._cli()
        if cli is None:
            return
        port = self.port_var.get()
        if not port:
            messagebox.showerror("No port", "Select a COM port above first.")
            return
        run_streaming([cli, "upload", "-p", port, "--fqbn", self.fqbn_entry.get(), "."],
                       self.log, cwd=self.sketch_entry.get())

    def compile_and_upload(self):
        cli = self._cli()
        if cli is None:
            return
        port = self.port_var.get()
        if not port:
            messagebox.showerror("No port", "Select a COM port above first.")
            return
        fqbn = self.fqbn_entry.get()
        sketch_dir = self.sketch_entry.get()

        def after_compile():
            run_streaming([cli, "upload", "-p", port, "--fqbn", fqbn, "."],
                           self.log, cwd=sketch_dir)

        run_streaming([cli, "compile", "--fqbn", fqbn, "."],
                       self.log, cwd=sketch_dir, on_done=after_compile)


# --------------------------------------------------------------------------
# Tab 2: Capture
# --------------------------------------------------------------------------

def parse_scan_row(line: str):
    """Parses one row of the ESP32's fixed-width scan table
    ('%-3d %-32s %-3d %-5d %-14s %02X:...' - see MarauderZ_sniffer.ino). Fixed
    column offsets are used (rather than splitting on whitespace) so SSIDs
    containing spaces parse correctly. Returns None if the line doesn't
    look like a table row (e.g. it's the header, a blank line, or the
    'Type the number...' prompt)."""
    if len(line) < 68:
        return None
    num = line[0:3].strip()
    ssid = line[4:36].rstrip()
    ch = line[37:40].strip()
    rssi = line[41:46].strip()
    enc = line[47:61].strip()
    bssid = line[62:79].strip()
    if not num.isdigit():
        return None
    if not re.match(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$", bssid):
        return None
    return (num, ssid, ch, rssi, enc, bssid)


class CaptureTab(ttk.Frame):
    def __init__(self, master, port_var: tk.StringVar):
        super().__init__(master, padding=10)
        self.port_var = port_var
        self._ser = None
        self._stop_event = threading.Event()
        self._pcap_file = None
        self._eapol_count = 0
        self._parsing_table = False
        self._table_queue: "queue.Queue" = queue.Queue()

        row = ttk.Frame(self)
        row.pack(fill="x")

        ttk.Label(row, text="COM port:").pack(side="left")
        self.port_combo = ttk.Combobox(row, textvariable=self.port_var, width=12, values=self._list_ports())
        self.port_combo.pack(side="left", padx=5)
        ttk.Button(row, text="Refresh", command=self.refresh_ports).pack(side="left", padx=5)

        ttk.Label(row, text="Baud:").pack(side="left", padx=(15, 0))
        self.baud_entry = ttk.Entry(row, width=8)
        self.baud_entry.insert(0, "115200")
        self.baud_entry.pack(side="left", padx=5)

        row2 = ttk.Frame(self)
        row2.pack(fill="x", pady=(8, 0))
        ttk.Label(row2, text="Output .pcap:").pack(side="left")
        self.pcap_entry = ttk.Entry(row2, width=45)
        self.pcap_entry.insert(0, str(CAPTURES_DIR / "handshake.pcap"))
        self.pcap_entry.pack(side="left", padx=5)
        ttk.Button(row2, text="Browse...",
                   command=lambda: browse_file(self.pcap_entry, save=True,
                                                filetypes=(("pcap files", "*.pcap"), ("All files", "*.*")),
                                                initialfile="handshake.pcap",
                                                initialdir=str(CAPTURES_DIR))).pack(side="left")

        btns = ttk.Frame(self)
        btns.pack(fill="x", pady=(10, 0))
        self.start_btn = ttk.Button(btns, text="Start Terminal", command=self.start_capture)
        self.start_btn.pack(side="left", padx=(0, 5))
        self.stop_btn = ttk.Button(btns, text="Stop Terminal", command=self.stop_capture, state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        ttk.Label(self, foreground="#a00",
                  text="Note: while the terminal is running, this COM port is locked and can't be opened by "
                       "another program (e.g. the Arduino Serial Monitor). Click Stop Terminal to release it."
                  ).pack(anchor="w", pady=(2, 8))

        esp_btns = ttk.Frame(self)
        esp_btns.pack(fill="x", pady=(0, 8))
        self.reset_btn = ttk.Button(esp_btns, text="Start (restart ESP32 from the beginning)",
                                     command=self.hard_reset, state="disabled")
        self.reset_btn.pack(side="left", padx=(0, 5))
        self.esp_stop_btn = ttk.Button(esp_btns, text="Stop (end deauth/capture, keep board on)",
                                        command=self.send_stop_command, state="disabled")
        self.esp_stop_btn.pack(side="left", padx=5)

        table_frame = ttk.LabelFrame(self, text="Scanned networks")
        table_frame.pack(fill="both", expand=False, pady=(0, 8))
        columns = ("num", "ssid", "ch", "rssi", "enc", "bssid")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        headings = {"num": "#", "ssid": "SSID", "ch": "CH", "rssi": "RSSI", "enc": "ENC", "bssid": "BSSID"}
        widths = {"num": 30, "ssid": 260, "ch": 40, "rssi": 50, "enc": 110, "bssid": 130}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="left", fill="y", pady=5)
        self.tree.bind("<Double-1>", lambda e: self.select_network())

        select_row = ttk.Frame(self)
        select_row.pack(fill="x", pady=(0, 8))
        ttk.Button(select_row, text="Select This Network", command=self.select_network).pack(side="left")
        ttk.Label(select_row, text="  (or double-click a row)").pack(side="left")

        send_row = ttk.Frame(self)
        send_row.pack(fill="x", pady=(0, 8))
        ttk.Label(send_row, text="Or send raw input to ESP32 ('r' to rescan, etc.):").pack(side="left")
        self.send_entry = ttk.Entry(send_row, width=10)
        self.send_entry.pack(side="left", padx=5)
        self.send_entry.bind("<Return>", lambda e: self.send_input())
        ttk.Button(send_row, text="Send", command=self.send_input).pack(side="left")

        self.log = LogPanel(self)
        self.log.pack(fill="both", expand=True)

        self.after(100, self._drain_table)

    def _list_ports(self):
        if serial is None:
            return []
        return [p.device for p in serial.tools.list_ports.comports()]

    def refresh_ports(self):
        self.port_combo["values"] = self._list_ports()

    def start_capture(self):
        if serial is None:
            messagebox.showerror("Missing dependency", "pyserial is not installed.\nRun: pip install pyserial")
            return
        port = self.port_var.get().strip()
        if not port:
            messagebox.showerror("No port", "Enter or select a COM port.")
            return
        try:
            baud = int(self.baud_entry.get())
        except ValueError:
            messagebox.showerror("Bad baud rate", "Baud rate must be a number.")
            return
        pcap_path = self.pcap_entry.get().strip()
        if not pcap_path:
            messagebox.showerror("No output file", "Choose an output .pcap path.")
            return

        try:
            self._ser = serial.Serial(port, baud, timeout=1)
        except Exception as e:
            messagebox.showerror("Serial error", str(e))
            return
        self._ser.dtr = False
        self._ser.rts = False

        self._pcap_file = open(pcap_path, "wb")
        write_pcap_header(self._pcap_file)
        self._pcap_file.flush()
        self._eapol_count = 0
        self._stop_event.clear()
        self._parsing_table = False
        self.tree.delete(*self.tree.get_children())

        self.log.clear()
        self.log.log(f"Connected to {port} @ {baud} baud, writing to {pcap_path}")
        self.log.log("Watch the 'Scanned networks' table below, then click a row and 'Select This Network'.")

        threading.Thread(target=self._reader_loop, daemon=True).start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.reset_btn.configure(state="normal")
        self.esp_stop_btn.configure(state="normal")

    def _reader_loop(self):
        while not self._stop_event.is_set():
            try:
                line = self._ser.readline().decode(errors="replace").rstrip("\r\n")
            except Exception:
                break
            if not line:
                continue
            if line.startswith("EAPOL:") or line.startswith("BEACON:"):
                tag, hexstr = line.split(":", 1)
                try:
                    data = bytes.fromhex(hexstr)
                except ValueError:
                    continue
                write_pcap_packet(self._pcap_file, data)
                self._pcap_file.flush()
                if tag == "EAPOL":
                    self._eapol_count += 1
                    self.log.log(f"[+] wrote EAPOL frame #{self._eapol_count} ({len(data)} bytes)")
                else:
                    self.log.log(f"[+] wrote BEACON frame ({len(data)} bytes)")
                continue

            self.log.log(line)

            stripped = line.strip()
            if stripped.startswith("#") and "SSID" in stripped:
                self._parsing_table = True
                self._table_queue.put(("clear", None))
                continue
            if self._parsing_table:
                row = parse_scan_row(line)
                if row is not None:
                    self._table_queue.put(("row", row))
                else:
                    self._parsing_table = False

    def _drain_table(self):
        while True:
            try:
                kind, payload = self._table_queue.get_nowait()
            except queue.Empty:
                break
            if kind == "clear":
                self.tree.delete(*self.tree.get_children())
            elif kind == "row":
                self.tree.insert("", "end", iid=payload[0], values=payload)
        self.after(100, self._drain_table)

    def select_network(self):
        if self._ser is None or not self._ser.is_open:
            messagebox.showerror("Not connected", "Start the terminal first.")
            return
        sel = self.tree.selection()
        if not sel:
            messagebox.showerror("No network selected", "Click a row in the table first.")
            return
        number = sel[0]
        self._ser.write((number + "\n").encode())
        self.log.log(f">> selected network #{number}")

    def send_input(self):
        if self._ser is None or not self._ser.is_open:
            messagebox.showerror("Not connected", "Start the terminal first.")
            return
        text = self.send_entry.get()
        self._ser.write((text + "\n").encode())
        self.log.log(f">> sent: {text}")
        self.send_entry.delete(0, tk.END)

    def hard_reset(self):
        """Hardware-resets the ESP32 via the CP2102/CH340 auto-reset circuit
        (pulses RTS, which pulls EN low) so the sketch runs from setup()
        again - a fresh scan, same as power-cycling the board. Needs no
        firmware support, unlike Stop below."""
        if self._ser is None or not self._ser.is_open:
            messagebox.showerror("Not connected", "Start the terminal first.")
            return
        self._parsing_table = False
        self.tree.delete(*self.tree.get_children())
        self._ser.dtr = False
        self._ser.rts = True
        time.sleep(0.1)
        self._ser.rts = False
        self.log.log(">> hardware reset pulsed - ESP32 restarting from setup() (fresh scan incoming)")

    def send_stop_command(self):
        """Sends the STOP command the firmware listens for (see
        checkSerialCommands() in MarauderZ_sniffer.ino), which halts the deauth
        burst / PMKID association loop and switches off promiscuous capture,
        without resetting the board or losing the current serial session."""
        if self._ser is None or not self._ser.is_open:
            messagebox.showerror("Not connected", "Start the terminal first.")
            return
        self._ser.write(b"STOP\n")
        self.log.log(">> sent STOP - deauth attack and packet capture halted on the ESP32")

    def stop_capture(self):
        self._stop_event.set()
        if self._ser is not None:
            try:
                self._ser.close()
            except Exception:
                pass
        if self._pcap_file is not None:
            self._pcap_file.close()
        self.log.log(f"\nDone. Captured {self._eapol_count} EAPOL frame(s).")
        if self._eapol_count < 4:
            self.log.log("Warning: fewer than 4 EAPOL frames captured - handshake may be incomplete.")
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.reset_btn.configure(state="disabled")
        self.esp_stop_btn.configure(state="disabled")


# --------------------------------------------------------------------------
# Tab 3: Convert
# --------------------------------------------------------------------------

class ConvertTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)

        ttk.Label(self, text="Input .pcap:").grid(row=0, column=0, sticky="w")
        self.pcap_entry = ttk.Entry(self, width=55)
        self.pcap_entry.insert(0, str(CAPTURES_DIR / "handshake.pcap"))
        self.pcap_entry.grid(row=1, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...",
                   command=lambda: browse_file(self.pcap_entry,
                                                filetypes=(("pcap files", "*.pcap"), ("All files", "*.*")),
                                                initialdir=str(CAPTURES_DIR))
                   ).grid(row=1, column=1)

        opA = ttk.LabelFrame(self, text="Option A - hashcat.net cap2hashcat (web, no install)")
        opA.grid(row=2, column=0, columnspan=2, sticky="we", pady=10)
        ttk.Label(opA, text="Opens the converter in your browser. Upload the .pcap above manually,\n"
                             "then download the result into the captures/ folder.",
                  justify="left").pack(anchor="w", padx=5, pady=5)
        ttk.Button(opA, text="Open cap2hashcat.net", command=self.open_web).pack(anchor="w", padx=5, pady=(0, 5))

        opB = ttk.LabelFrame(self, text="Option B - hcxtools via WSL (fully local)")
        opB.grid(row=3, column=0, columnspan=2, sticky="we")
        ttk.Label(opB, text="Requires WSL + Ubuntu with hcxtools installed (see README).",
                  justify="left").grid(row=0, column=0, columnspan=2, sticky="w", padx=5, pady=(5, 8))

        ttk.Label(opB, text="Save output .hc22000 to:").grid(row=1, column=0, sticky="w", padx=5)
        self.out_entry = ttk.Entry(opB, width=48)
        self.out_entry.insert(0, str(CAPTURES_DIR / "handshake.hc22000"))
        self.out_entry.grid(row=2, column=0, sticky="we", padx=5)
        ttk.Button(opB, text="Browse...",
                   command=lambda: browse_file(self.out_entry, save=True,
                                                filetypes=(("hc22000 files", "*.hc22000"), ("All files", "*.*")),
                                                initialfile="handshake.hc22000",
                                                initialdir=str(CAPTURES_DIR))
                   ).grid(row=2, column=1, padx=(0, 5))
        ttk.Button(opB, text="Convert via WSL (saves to the path above)", command=self.convert_wsl).grid(
            row=3, column=0, sticky="w", padx=5, pady=(8, 5))
        opB.columnconfigure(0, weight=1)

        self.log = LogPanel(self)
        self.log.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=(10, 0))
        self.rowconfigure(4, weight=1)
        self.columnconfigure(0, weight=1)

    def open_web(self):
        webbrowser.open("https://hashcat.net/cap2hashcat/")
        self.log.log(f"Opened cap2hashcat.net - upload: {self.pcap_entry.get()}")

    def convert_wsl(self):
        pcap = self.pcap_entry.get().strip()
        out = self.out_entry.get().strip()
        if not pcap or not os.path.isfile(pcap):
            messagebox.showerror("File not found", "Choose a valid input .pcap file.")
            return
        if not out:
            messagebox.showerror("No output path", "Choose where to save the .hc22000 file.")
            return
        try:
            wsl_in = win_path_to_wsl(pcap)
            wsl_out = win_path_to_wsl(out)
        except Exception as e:
            messagebox.showerror("Path error", str(e))
            return
        cmd = ["wsl", "-d", "Ubuntu", "--", "hcxpcapngtool", "-o", wsl_out, wsl_in]

        def on_done():
            if os.path.isfile(out):
                self.log.log(f"Saved hc22000 file to: {out}")
                messagebox.showinfo("Saved", f"hc22000 file saved to:\n{out}")
            else:
                self.log.log("No output file was produced - check the log above for errors.")

        run_streaming(cmd, self.log, on_done=on_done)


# --------------------------------------------------------------------------
# Tab 4: Inspect & Isolate
# --------------------------------------------------------------------------

class InspectIsolateTab(ttk.Frame):
    """Combines listing a hc22000 file's entries and isolating one SSID
    into it, since they're always done back-to-back against the same
    file. Isolating is driven by selecting a row in the entries table,
    rather than retyping the SSID by hand."""

    def __init__(self, master):
        super().__init__(master, padding=10)
        self._row_lines = {}  # treeview iid -> raw line text, for isolate

        top = ttk.Frame(self)
        top.pack(fill="x")
        ttk.Label(top, text="hc22000 file:").grid(row=0, column=0, sticky="w")
        self.hc_entry = ttk.Entry(top, width=55)
        self.hc_entry.grid(row=1, column=0, sticky="we", padx=(0, 5))
        ttk.Button(top, text="Browse...",
                   command=lambda: browse_file(self.hc_entry,
                                                filetypes=(("hc22000 files", "*.hc22000 *.22000"), ("All files", "*.*")),
                                                initialdir=str(CAPTURES_DIR))
                   ).grid(row=1, column=1)
        ttk.Button(top, text="List Entries", command=self.list_entries).grid(
            row=2, column=0, sticky="w", pady=(5, 8))
        top.columnconfigure(0, weight=1)

        table_frame = ttk.LabelFrame(self, text="Networks found in this file - select one to isolate")
        table_frame.pack(fill="both", expand=False, pady=(0, 8))
        columns = ("line", "bssid", "essid")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=6)
        headings = {"line": "#", "bssid": "BSSID", "essid": "ESSID"}
        widths = {"line": 40, "bssid": 130, "essid": 300}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="left", fill="y", pady=5)
        self.tree.bind("<Double-1>", lambda e: self.isolate_selected())

        isolate_box = ttk.LabelFrame(self, text="Isolate the selected network")
        isolate_box.pack(fill="x")
        ttk.Label(isolate_box, text="Output file:").grid(row=0, column=0, sticky="w", padx=5, pady=(5, 0))
        self.out_entry = ttk.Entry(isolate_box, width=55)
        self.out_entry.insert(0, str(CAPTURES_DIR / "target-network.22000"))
        self.out_entry.grid(row=1, column=0, sticky="we", padx=5)
        ttk.Button(isolate_box, text="Browse...",
                   command=lambda: browse_file(self.out_entry, save=True,
                                                filetypes=(("22000 files", "*.22000"), ("All files", "*.*")),
                                                initialfile="target-network.22000",
                                                initialdir=str(CAPTURES_DIR))
                   ).grid(row=1, column=1, padx=(0, 5))
        ttk.Button(isolate_box, text="Isolate Selected Network", command=self.isolate_selected).grid(
            row=2, column=0, sticky="w", padx=5, pady=5)
        ttk.Label(isolate_box, text="(or double-click a row above)").grid(row=2, column=1, sticky="w")
        isolate_box.columnconfigure(0, weight=1)

        self.log = LogPanel(self)
        self.log.pack(fill="both", expand=True, pady=(10, 0))

    def list_entries(self):
        path = self.hc_entry.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("File not found", "Choose a valid hc22000 file first.")
            return
        self.log.clear()
        self.tree.delete(*self.tree.get_children())
        self._row_lines.clear()
        try:
            with open(path) as f:
                lines = [l for l in f if l.strip()]
            if not lines:
                self.log.log("File is empty - no hashes found.")
                return
            for i, line in enumerate(lines):
                try:
                    bssid, essid, _ = parse_hc22000_line(line)
                except Exception:
                    self.log.log(f"line {i}: (could not parse)")
                    continue
                iid = str(i)
                self.tree.insert("", "end", iid=iid, values=(i, bssid, essid))
                self._row_lines[iid] = line
            self.log.log(f"Found {len(self._row_lines)} entr{'y' if len(self._row_lines) == 1 else 'ies'}. "
                          "Select a row and click Isolate Selected Network.")
        except Exception as e:
            self.log.log(f"[error] {e}")

    def isolate_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showerror("No network selected", "Click a row in the table first (after List Entries).")
            return
        line = self._row_lines.get(sel[0])
        if line is None:
            messagebox.showerror("Row not found", "Click List Entries again, then select a row.")
            return
        out_path = self.out_entry.get().strip()
        if not out_path:
            messagebox.showerror("No output", "Choose an output file path.")
            return

        bssid, essid, essid_hex = parse_hc22000_line(line)
        with open(out_path, "w") as f_out:
            f_out.write(line if line.endswith("\n") else line + "\n")

        self.log.clear()
        self.log.log(f"Isolated \"{essid}\" (BSSID {bssid}, hex {essid_hex}) to {out_path}")


# --------------------------------------------------------------------------
# Tab 6: Crack
# --------------------------------------------------------------------------

class CrackTab(ttk.Frame):
    def __init__(self, master, cracked_var: tk.StringVar):
        super().__init__(master, padding=10)
        self._proc = None
        self._user_stopped = False
        self.cracked_var = cracked_var

        ttk.Label(self, text="hashcat.exe:").grid(row=0, column=0, sticky="w")
        self.hc_exe_entry = ttk.Entry(self, width=55)
        self.hc_exe_entry.grid(row=1, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...",
                   command=lambda: browse_file(self.hc_exe_entry,
                                                filetypes=(("hashcat.exe", "hashcat.exe"), ("All files", "*.*")),
                                                initialdir=str(DOWNLOADS_DIR))
                   ).grid(row=1, column=1)

        ttk.Label(self, text="Hash file (.hc22000 / .22000):").grid(row=2, column=0, sticky="w", pady=(10, 0))
        self.hash_entry = ttk.Entry(self, width=55)
        self.hash_entry.grid(row=3, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...",
                   command=lambda: browse_file(self.hash_entry,
                                                filetypes=(("hash files", "*.hc22000 *.22000"), ("All files", "*.*")),
                                                initialdir=str(CAPTURES_DIR))
                   ).grid(row=3, column=1)

        ttk.Label(self, text="Wordlist:").grid(row=4, column=0, sticky="w", pady=(10, 0))
        self.wordlist_entry = ttk.Entry(self, width=55)
        self.wordlist_entry.insert(0, str(DOWNLOADS_DIR / "rockyou.txt"))
        self.wordlist_entry.grid(row=5, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...",
                   command=lambda: browse_file(self.wordlist_entry,
                                                filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
                                                initialdir=str(DOWNLOADS_DIR))
                   ).grid(row=5, column=1)

        ttk.Label(self, text="Output file:").grid(row=6, column=0, sticky="w", pady=(10, 0))
        self.out_entry = ttk.Entry(self, width=55, textvariable=self.cracked_var)
        self.out_entry.grid(row=7, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...",
                   command=lambda: browse_file(self.out_entry, save=True,
                                                filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
                                                initialfile="cracked.txt",
                                                initialdir=str(CAPTURES_DIR))
                   ).grid(row=7, column=1)

        ttk.Label(self, text="Extra hashcat args (optional, e.g. -r rules\\best64.rule):").grid(
            row=8, column=0, sticky="w", pady=(10, 0))
        self.extra_entry = ttk.Entry(self, width=55)
        self.extra_entry.grid(row=9, column=0, sticky="we")

        btns = ttk.Frame(self)
        btns.grid(row=10, column=0, columnspan=2, pady=10, sticky="w")
        self.start_btn = ttk.Button(btns, text="Start Cracking", command=self.start_crack)
        self.start_btn.pack(side="left", padx=(0, 5))
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_crack, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        ttk.Button(btns, text="Show Cracked (--show)", command=self.show_cracked).pack(side="left", padx=5)
        ttk.Button(btns, text="Save cracked.txt As...", command=self.save_as).pack(side="left", padx=5)

        self.result_var = tk.StringVar(value="")
        self.result_label = ttk.Label(self, textvariable=self.result_var,
                                       font=("Segoe UI", 18, "bold"), foreground="#0a7d1f")
        self.result_label.grid(row=11, column=0, columnspan=2, sticky="w", pady=(0, 5))

        self.log = LogPanel(self)
        self.log.grid(row=12, column=0, columnspan=2, sticky="nsew")
        self.rowconfigure(12, weight=1)
        self.columnconfigure(0, weight=1)

    def _hashcat_paths(self):
        """Returns (absolute exe path, its folder) or (None, None). Always
        pass the *full* exe path as argv[0] - a bare 'hashcat.exe' is
        resolved against this GUI's own working directory, not the folder
        we cwd the child process into, and fails with FileNotFoundError
        whenever the GUI wasn't launched from inside/near that folder
        (this is why cracked output could silently never get produced)."""
        exe = self.hc_exe_entry.get().strip()
        if not exe or not os.path.isfile(exe):
            messagebox.showerror("hashcat.exe not found", "Browse to a valid hashcat.exe first.")
            return None, None
        exe_abs = str(Path(exe).resolve())
        return exe_abs, str(Path(exe_abs).parent)

    def start_crack(self):
        exe_abs, hc_dir = self._hashcat_paths()
        if exe_abs is None:
            return
        hash_file = self.hash_entry.get().strip()
        wordlist = self.wordlist_entry.get().strip()
        out_file = self.out_entry.get().strip()
        if not hash_file or not os.path.isfile(hash_file):
            messagebox.showerror("Hash file not found", "Browse to a valid hash file.")
            return
        if not wordlist or not os.path.isfile(wordlist):
            messagebox.showerror("Wordlist not found", "Browse to a valid wordlist.")
            return

        cmd = [exe_abs, "-m", "22000", os.path.abspath(hash_file), os.path.abspath(wordlist)]
        if out_file:
            cmd += ["-o", os.path.abspath(out_file)]
        extra = self.extra_entry.get().strip()
        if extra:
            cmd += extra.split()

        self.log.clear()
        self.result_var.set("")
        self.log.log("Note: running from inside the hashcat folder so it can find OpenCL/kernels.")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self._user_stopped = False

        def on_done():
            self.start_btn.configure(state="normal")
            self.stop_btn.configure(state="disabled")
            self._proc = None
            if not self._user_stopped:
                self._report_result(exe_abs, hc_dir, hash_file, out_file)

        self._run_tracked(cmd, hc_dir, on_done)

    def _report_result(self, exe_abs, hc_dir, hash_file, out_file):
        """Determines the real result via 'hashcat --show' rather than just
        checking whether -o got written. If a hash was already cracked in
        an earlier run, hashcat finds it in its potfile, prints "All hashes
        found as potfile..." and skips writing -o entirely (and exits
        non-zero) - checking -o alone would wrongly report "not cracked"
        for a password that actually was found, and cracked.txt would
        never end up populated. --show always reports the true state
        regardless of which path hashcat took."""
        password = None
        try:
            r = subprocess.run(
                [exe_abs, "-m", "22000", os.path.abspath(hash_file), "--show"],
                cwd=hc_dir, capture_output=True, text=True, timeout=60,
            )
            first_line = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
            if first_line:
                password = first_line.rsplit(":", 1)[-1]
                if out_file and (not os.path.isfile(out_file) or not os.path.getsize(out_file)):
                    with open(out_file, "w") as f:
                        f.write(first_line + "\n")
        except Exception as e:
            self.log.log(f"[error checking result] {e}")

        if password:
            self.result_var.set(f"CRACKED - password: {password}")
            self.result_label.configure(foreground="#0a7d1f")
            messagebox.showinfo("Cracked!", f"Password found:\n\n{password}")
        else:
            self.result_var.set("No password found in the wordlist.")
            self.result_label.configure(foreground="#a00")
            messagebox.showwarning("Not cracked", "No password found in the wordlist for this network.")

    def _run_tracked(self, cmd, cwd, on_done):
        def worker():
            self.log.log(f"$ {' '.join(cmd)}   (cwd={cwd})")
            try:
                self._proc = subprocess.Popen(
                    cmd, cwd=cwd,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
                for line in self._proc.stdout:
                    self.log.log(line)
                self._proc.wait()
                self.log.log(f"[exit code {self._proc.returncode}]")
            except Exception as e:
                self.log.log(f"[error] {e}")
            finally:
                on_done()

        threading.Thread(target=worker, daemon=True).start()

    def stop_crack(self):
        if self._proc is not None:
            self._user_stopped = True
            self._proc.terminate()
            self.log.log("[stopped by user]")

    def show_cracked(self):
        exe_abs, hc_dir = self._hashcat_paths()
        if exe_abs is None:
            return
        hash_file = self.hash_entry.get().strip()
        if not hash_file or not os.path.isfile(hash_file):
            messagebox.showerror("Hash file not found", "Browse to a valid hash file.")
            return
        cmd = [exe_abs, "-m", "22000", os.path.abspath(hash_file), "--show"]
        run_streaming(cmd, self.log, cwd=hc_dir)

    def save_as(self):
        src = self.out_entry.get().strip()
        if not src or not os.path.isfile(src):
            messagebox.showerror("Nothing to save", "No cracked output file yet - run a crack first.")
            return
        dest = filedialog.asksaveasfilename(
            defaultextension=".txt", initialfile="cracked.txt",
            filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
            initialdir=str(CAPTURES_DIR),
        )
        if not dest:
            return
        shutil.copy2(src, dest)
        self.cracked_var.set(dest)
        self.log.log(f"Saved cracked results to {dest} (also loaded into the Results tab)")


# --------------------------------------------------------------------------
# Tab 7: Results
# --------------------------------------------------------------------------

class ResultsTab(ttk.Frame):
    def __init__(self, master, cracked_var: tk.StringVar):
        super().__init__(master, padding=10)

        ttk.Label(self, text="cracked.txt:").grid(row=0, column=0, sticky="w")
        self.file_entry = ttk.Entry(self, width=55, textvariable=cracked_var)
        self.file_entry.grid(row=1, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...",
                   command=lambda: browse_file(self.file_entry,
                                                filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
                                                initialdir=str(CAPTURES_DIR))
                   ).grid(row=1, column=1)
        ttk.Button(self, text="Load", command=self.load).grid(row=2, column=0, sticky="w", pady=10)

        self.log = LogPanel(self)
        self.log.grid(row=3, column=0, columnspan=2, sticky="nsew")
        self.rowconfigure(3, weight=1)
        self.columnconfigure(0, weight=1)

        ttk.Label(self, text="Format: PMKID/MIC : AP-MAC : client-MAC : ESSID : password",
                  foreground="#888").grid(row=4, column=0, columnspan=2, sticky="w", pady=(5, 0))

    def load(self):
        path = self.file_entry.get().strip()
        self.log.clear()
        if not path or not os.path.isfile(path):
            self.log.log("File not found - nothing cracked yet, or wrong path.")
            return
        with open(path) as f:
            content = f.read().strip()
        if not content:
            self.log.log("File is empty - not cracked yet.")
            return
        for line in content.splitlines():
            self.log.log(line)
            parts = line.split(":")
            if len(parts) >= 5:
                self.log.log(f"  -> ESSID={parts[3]}  PASSWORD={parts[4]}")


# --------------------------------------------------------------------------
# Main window
# --------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MarauderZ for Windows PC")
        self.geometry("880x680")

        logo_path = PHOTOS_DIR / "logo.png"
        if logo_path.is_file():
            # Kept as an attribute, not a local - PhotoImage is garbage
            # collected (and the label goes blank) as soon as nothing
            # holds a reference to it.
            self.logo_img = tk.PhotoImage(file=str(logo_path)).subsample(12, 12)
            self.iconphoto(True, self.logo_img)
            header = ttk.Frame(self)
            header.pack(fill="x", padx=8, pady=(8, 0))
            ttk.Label(header, image=self.logo_img).pack()
            ttk.Label(header, text="MarauderZ", font=("Segoe UI", 16, "bold")).pack()

        warning = ttk.Label(
            self,
            text="Only target networks and clients you own or are explicitly authorized to test.",
            foreground="white", background="#b00020", anchor="center", padding=6,
        )
        warning.pack(fill="x")

        port_var = tk.StringVar()
        cracked_var = tk.StringVar(value=str(CAPTURES_DIR / "cracked.txt"))

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        notebook.add(FlashTab(notebook, port_var), text="1. Flash")
        notebook.add(CaptureTab(notebook, port_var), text="2. Capture")
        notebook.add(ConvertTab(notebook), text="3. Convert")
        notebook.add(InspectIsolateTab(notebook), text="4. Inspect & Isolate")
        notebook.add(CrackTab(notebook, cracked_var), text="5. Crack")
        notebook.add(ResultsTab(notebook, cracked_var), text="6. Results")


def main():
    if serial is None:
        print("Warning: pyserial is not installed. Run: pip install pyserial", file=sys.stderr)
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
