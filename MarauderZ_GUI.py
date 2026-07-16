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
# in - so captures/downloads/firmware must anchor on sys.executable instead
# (they're user-writable/next-to-the-exe by design). photos/ is different:
# it's read-only branding (logo.ico/logo.png) that must work even if someone
# only has the standalone exe (downloaded from a GitHub release, sent as a
# single file, etc.) with no photos/ folder alongside it - so it's bundled
# into the exe itself (see build_exe.ps1's --add-data) and read back from
# PyInstaller's onefile extraction dir (sys._MEIPASS) instead.
if getattr(sys, "frozen", False):
    PROJECT_DIR = Path(sys.executable).resolve().parent
    ASSETS_DIR = Path(getattr(sys, "_MEIPASS", PROJECT_DIR))
else:
    PROJECT_DIR = Path(__file__).resolve().parent
    ASSETS_DIR = PROJECT_DIR
FIRMWARE_DIR = PROJECT_DIR / "firmware"
DOWNLOADS_DIR = PROJECT_DIR / "downloads"   # third-party downloads: hashcat, rockyou.txt
CAPTURES_DIR = PROJECT_DIR / "captures"     # your own run output: pcap, hc22000, cracked.txt
PHOTOS_DIR = ASSETS_DIR / "photos"

# These hold your own capture data / downloaded tools, not source - see
# .gitignore. Created here so the GUI's default save/open paths always
# resolve even on a freshly cloned repo.
CAPTURES_DIR.mkdir(exist_ok=True)
DOWNLOADS_DIR.mkdir(exist_ok=True)

MASK_HELP_TEXT = r"""MASK / BRUTE-FORCE (-a 3) CHARACTER SETS
==========================================
?l  lowercase letters        a-z
?u  uppercase letters        A-Z
?d  digits                   0-9
?s  special characters       !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ (and space)
?a  all of the above         ?l?u?d?s
?b  every byte value         0x00 - 0xff

Each ?X in your mask = one character position using that set.
Example: ?d?d?d?d = a 4-digit brute-force (0000-9999).

CUSTOM CHARSETS (-1 -2 -3 -4)
==========================================
Define your own character set and reference it as ?1 / ?2 / ?3 / ?4 in the
mask. Put these in "Extra hashcat args" alongside the mask.

  -1 123456789
  mask: ?1?d?d?d?d?d?d?d?d?d
     -> 10-digit number where the FIRST digit can't be 0

  -1 0123456789 -2 123456789
  mask: 9?2?1?1?1?1?1?1?1?1
     -> starts with 9, second digit 1-9, rest 0-9

EXAMPLE MASKS FOR PHONE-NUMBER STYLE BRUTE FORCE
==========================================
?d?d?d?d?d?d?d?d?d?d        any 10-digit number (10,000,000,000 combos)
9?d?d?d?d?d?d?d?d?d         10-digit, starts with 9   (1,000,000,000 combos)
8?d?d?d?d?d?d?d?d?d         10-digit, starts with 8
98765?d?d?d?d?d              fix a known 5-digit prefix, brute the rest
                              (100,000 combos - seconds instead of hours)

Every fixed digit divides the remaining keyspace (and time) by 10 - the
biggest speed win comes from knowing any part of the real number, not from
GPU power.

MASK LENGTH / POSITION SYNTAX
==========================================
Each position in the mask = one character. A 10-digit mask needs 10 ?d
tokens. You can mix literal characters with ?X tokens, e.g. 555?d?d?d?d?d?d?d
fixes an area code "555" then brutes the remaining 7 digits.

--increment / --increment-min / --increment-max
==========================================
Tries shorter masks first, from --increment-min up to the mask's full length.
Put in "Extra hashcat args":

  --increment --increment-min 8 --increment-max 10
     -> with mask ?d?d?d?d?d?d?d?d?d?d, tries all 8-digit numbers, then
        9-digit, then 10-digit

OTHER ATTACK MODES (for reference - this GUI only exposes -a 0 / -a 3)
==========================================
-a 0   Dictionary   - wordlist of candidate passwords
-a 3   Mask         - brute-force using the character sets above
-a 6   Hybrid       - wordlist word + mask appended   (word + ?d?d?d?d)
-a 7   Hybrid       - mask + wordlist word appended   (?d?d?d?d + word)

USEFUL EXTRA HASHCAT FLAGS (put in "Extra hashcat args")
==========================================
-O                     optimized kernel, needs less GPU memory
                        (safe here since phone-number masks are well under
                        its ~32-char password-length limit)
-w 1..4                workload profile; higher = more aggressive/hotter
--runtime=N             auto-stop after N seconds (handy for a quick test)
-r rules\best64.rule   apply a rule file to mutate wordlist entries
                        (dictionary mode only, not mask mode)
"""


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

_MASK_CHARSET_SIZES = {"l": 26, "u": 26, "d": 10, "s": 33, "a": 95, "b": 256}


def mask_keyspace(mask: str, custom_charsets=None):
    """Total candidate count for a hashcat mask, e.g. '?d?d?d?d' -> 10000.
    custom_charsets maps '1'-'4' to the literal charset string defined by
    -1/-2/-3/-4 (only their length matters here)."""
    custom_charsets = custom_charsets or {}
    total = 1
    i = 0
    while i < len(mask):
        if mask[i] == "?" and i + 1 < len(mask):
            token = mask[i + 1]
            if token in _MASK_CHARSET_SIZES:
                total *= _MASK_CHARSET_SIZES[token]
                i += 2
                continue
            if token in custom_charsets:
                total *= max(len(custom_charsets[token]), 1)
                i += 2
                continue
        i += 1
    return total


def parse_hashrate(text: str):
    """Parses a hashcat speed string like '199.6 kH/s' into a plain H/s
    float, or None if it doesn't look like one."""
    m = re.match(r"([\d.,]+)\s*(\S?)H/s", text.strip())
    if not m:
        return None
    value = float(m.group(1).replace(",", ""))
    mult = {"": 1, "k": 1e3, "m": 1e6, "g": 1e9, "t": 1e12}.get(m.group(2).lower(), 1)
    return value * mult


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    return f"{days / 365.25:.1f} years"


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


def hashcat_env():
    """Copy of os.environ with any installed CUDA Toolkit's bin/bin\\x64 dirs
    prepended to PATH. nvrtc*.dll (needed for hashcat's fast CUDA backend)
    lives in bin\\x64, and a process started before/without a fresh
    login won't see a PATH update the installer made - without this,
    hashcat silently falls back to the slower OpenCL backend or fails
    with 'CUDA SDK Toolkit not installed or incorrectly installed'
    even right after installing it."""
    env = os.environ.copy()
    cuda_root = Path(r"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA")
    if cuda_root.is_dir():
        for v in sorted((d for d in cuda_root.iterdir() if d.is_dir()), reverse=True):
            bin_x64 = v / "bin" / "x64"
            if bin_x64.is_dir():
                env["PATH"] = f"{bin_x64}{os.pathsep}{v / 'bin'}{os.pathsep}{env.get('PATH', '')}"
                break
    return env


def run_streaming(cmd, log: LogPanel, cwd=None, on_done=None, shell=False, env=None):
    """Runs cmd in a background thread, streaming stdout/stderr into log."""

    def worker():
        log.log(f"$ {cmd if isinstance(cmd, str) else ' '.join(cmd)}")
        try:
            proc = subprocess.Popen(
                cmd, cwd=cwd, shell=shell, env=env,
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


class ScrollableTab(ttk.Frame):
    """Wraps a tab-content frame in a canvas + vertical scrollbar, so any
    tab whose content is taller than the window still has everything
    reachable instead of getting clipped at the bottom. Used for every
    notebook tab (see App.__init__) rather than resizing widgets down or
    forcing the window itself to grow to fit the tallest tab."""

    def __init__(self, master, tab_cls, *args, **kwargs):
        super().__init__(master)
        canvas = tk.Canvas(self, highlightthickness=0)
        vbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=vbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        vbar.pack(side="right", fill="y")

        self.inner = tab_cls(canvas, *args, **kwargs)
        window_id = canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind(
            "<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(window_id, width=e.width))

        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        # Only hijack the mouse wheel while the pointer is actually over
        # this tab's canvas - bind_all is global, so without this a tab
        # created later would steal wheel-scroll from every earlier tab.
        canvas.bind("<Enter>", lambda _e: canvas.bind_all("<MouseWheel>", on_mousewheel))
        canvas.bind("<Leave>", lambda _e: canvas.unbind_all("<MouseWheel>"))


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

        ttk.Label(self, text="Attack mode:").grid(row=4, column=0, sticky="w", pady=(10, 0))
        mode_frame = ttk.Frame(self)
        mode_frame.grid(row=5, column=0, columnspan=2, sticky="w")
        self.attack_mode = tk.StringVar(value="dict")
        ttk.Radiobutton(mode_frame, text="Dictionary (-a 0, wordlist)", variable=self.attack_mode,
                         value="dict", command=self._update_mode).pack(side="left", padx=(0, 15))
        ttk.Radiobutton(mode_frame, text="Mask / brute-force (-a 3)", variable=self.attack_mode,
                         value="mask", command=self._update_mode).pack(side="left")

        ttk.Label(self, text="Wordlist:").grid(row=6, column=0, sticky="w", pady=(10, 0))
        self.wordlist_entry = ttk.Entry(self, width=55)
        self.wordlist_entry.insert(0, str(DOWNLOADS_DIR / "rockyou.txt"))
        self.wordlist_entry.grid(row=7, column=0, sticky="we", padx=(0, 5))
        self.wordlist_browse_btn = ttk.Button(
            self, text="Browse...",
            command=lambda: browse_file(self.wordlist_entry,
                                         filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
                                         initialdir=str(DOWNLOADS_DIR)))
        self.wordlist_browse_btn.grid(row=7, column=1)

        ttk.Label(self, text="Mask (?d=digit ?l=lower ?u=upper ?s=symbol ?a=all):").grid(
            row=8, column=0, sticky="w", pady=(10, 0))
        self.mask_entry = ttk.Entry(self, width=55, state="disabled")
        self.mask_entry.grid(row=9, column=0, sticky="we", padx=(0, 5))
        preset_frame = ttk.Frame(self)
        preset_frame.grid(row=9, column=1)
        self.mask_preset9_btn = ttk.Button(preset_frame, text="Starts with 9", state="disabled",
                                            command=self._insert_phone9_mask)
        self.mask_preset9_btn.pack(side="left")
        ttk.Button(preset_frame, text="Rules / Mask Help...", command=self.show_mask_help).pack(
            side="left", padx=(3, 0))

        ttk.Label(self, text="GPU/device (-d):").grid(row=10, column=0, sticky="w", pady=(10, 0))
        device_frame = ttk.Frame(self)
        device_frame.grid(row=11, column=0, columnspan=2, sticky="we")
        self.device_var = tk.StringVar(value="Auto (let hashcat choose)")
        self.device_combo = ttk.Combobox(device_frame, textvariable=self.device_var, width=48, state="readonly")
        self.device_combo["values"] = ("Auto (let hashcat choose)",)
        self.device_combo.pack(side="left", padx=(0, 5))
        ttk.Button(device_frame, text="Detect Devices", command=self.detect_devices).pack(side="left")

        ttk.Label(self, text="Output file:").grid(row=12, column=0, sticky="w", pady=(10, 0))
        self.out_entry = ttk.Entry(self, width=55, textvariable=self.cracked_var)
        self.out_entry.grid(row=13, column=0, sticky="we", padx=(0, 5))
        ttk.Button(self, text="Browse...",
                   command=lambda: browse_file(self.out_entry, save=True,
                                                filetypes=(("Text files", "*.txt"), ("All files", "*.*")),
                                                initialfile="cracked.txt",
                                                initialdir=str(CAPTURES_DIR))
                   ).grid(row=13, column=1)

        ttk.Label(self, text="Extra hashcat args (optional, e.g. -r rules\\best64.rule):").grid(
            row=14, column=0, sticky="w", pady=(10, 0))
        self.extra_entry = ttk.Entry(self, width=55)
        self.extra_entry.grid(row=15, column=0, sticky="we")

        btns = ttk.Frame(self)
        btns.grid(row=16, column=0, columnspan=2, pady=10, sticky="w")
        self.start_btn = ttk.Button(btns, text="Start Cracking", command=self.start_crack)
        self.start_btn.pack(side="left", padx=(0, 5))
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_crack, state="disabled")
        self.stop_btn.pack(side="left", padx=5)
        ttk.Button(btns, text="Show Cracked (--show)", command=self.show_cracked).pack(side="left", padx=5)
        ttk.Button(btns, text="Save cracked.txt As...", command=self.save_as).pack(side="left", padx=5)
        self.estimate_btn = ttk.Button(btns, text="Estimate Time...", command=self.estimate_time)
        self.estimate_btn.pack(side="left", padx=5)

        self.progress_var = tk.DoubleVar(value=0.0)
        self.progress_bar = ttk.Progressbar(self, orient="horizontal", mode="determinate",
                                             maximum=100, variable=self.progress_var)
        self.progress_bar.grid(row=17, column=0, columnspan=2, sticky="we", pady=(10, 0))

        self.progress_text_var = tk.StringVar(value="Progress: -- | Remaining: -- | Finishes: --")
        ttk.Label(self, textvariable=self.progress_text_var).grid(
            row=18, column=0, columnspan=2, sticky="w")
        self._last_progress = (0, 0, 0.0)
        self._last_eta = ("", "")

        self.gpu_status_var = tk.StringVar(value="GPU status: not running yet.")
        self.gpu_status_label = ttk.Label(self, textvariable=self.gpu_status_var,
                                           font=("Consolas", 10))
        self.gpu_status_label.grid(row=19, column=0, columnspan=2, sticky="w", pady=(0, 5))
        self._status_queue: "queue.Queue[tuple]" = queue.Queue()
        self.after(300, self._drain_gpu_status)

        self.result_var = tk.StringVar(value="")
        self.result_label = ttk.Label(self, textvariable=self.result_var,
                                       font=("Segoe UI", 18, "bold"), foreground="#0a7d1f")
        self.result_label.grid(row=20, column=0, columnspan=2, sticky="w", pady=(0, 5))

        self.log = LogPanel(self)
        self.log.grid(row=21, column=0, columnspan=2, sticky="nsew")
        self.rowconfigure(21, weight=1)
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

    def _update_mode(self):
        if self.attack_mode.get() == "dict":
            self.wordlist_entry.configure(state="normal")
            self.wordlist_browse_btn.configure(state="normal")
            self.mask_entry.configure(state="disabled")
            self.mask_preset9_btn.configure(state="disabled")
        else:
            self.wordlist_entry.configure(state="disabled")
            self.wordlist_browse_btn.configure(state="disabled")
            self.mask_entry.configure(state="normal")
            self.mask_preset9_btn.configure(state="normal")

    def _insert_phone9_mask(self):
        self.mask_entry.delete(0, tk.END)
        self.mask_entry.insert(0, "9" + "?d" * 9)

    def show_mask_help(self):
        """Reference popup for mask syntax and other hashcat brute-force
        knobs - a resizable window with a scrollbar since the reference
        text is long. Kept as a separate Toplevel (not squeezed into the
        main tab) so it can be left open side-by-side while editing masks."""
        win = tk.Toplevel(self)
        win.title("Mask / Brute-force Rules Reference")
        win.geometry("700x520")
        win.minsize(420, 300)

        text = scrolledtext.ScrolledText(win, wrap="word", font=("Consolas", 9))
        text.pack(fill="both", expand=True, padx=8, pady=8)
        text.insert("1.0", MASK_HELP_TEXT)
        text.configure(state="disabled")

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=(0, 8))

    def _get_custom_charsets(self):
        """Pulls -1/-2/-3/-4 custom charset definitions out of the Extra
        hashcat args field, e.g. '-1 123456789' -> {'1': '123456789'},
        so mask_keyspace() can size ?1-?4 tokens correctly."""
        extra = self.extra_entry.get()
        return {m.group(1): m.group(2) for m in re.finditer(r"-([1-4])\s+(\S+)", extra)}

    def estimate_time(self):
        """Computes the keyspace for the current mask (or wordlist line
        count for dictionary mode), benchmarks the selected device for
        this hash mode, and shows the estimated time to try every
        candidate - the direct answer to 'how long will this take'."""
        exe_abs, hc_dir = self._hashcat_paths()
        if exe_abs is None:
            return

        if self.attack_mode.get() == "mask":
            mask = self.mask_entry.get().strip()
            if not mask:
                messagebox.showerror("No mask", "Enter a mask first (or click 'Starts with 9').")
                return
            keyspace = mask_keyspace(mask, self._get_custom_charsets())
            keyspace_desc = f"mask '{mask}'"
        else:
            wordlist = self.wordlist_entry.get().strip()
            if not wordlist or not os.path.isfile(wordlist):
                messagebox.showerror("Wordlist not found", "Browse to a valid wordlist first.")
                return
            self.log.log(f"Counting lines in {wordlist} for the time estimate...")
            with open(wordlist, "rb") as f:
                keyspace = sum(1 for _ in f)
            keyspace_desc = f"wordlist ({keyspace:,} lines)"

        device_sel = self.device_var.get().strip()
        bench_cmd = [exe_abs, "-b", "-m", "22000"]
        if device_sel and not device_sel.startswith("Auto"):
            bench_cmd += ["-d", device_sel.split(":", 1)[0].strip()]

        self.estimate_btn.configure(state="disabled")
        self.gpu_status_var.set("GPU status: benchmarking for time estimate, please wait...")
        self.log.log(f"$ {' '.join(bench_cmd)}   (cwd={hc_dir})")

        def worker():
            hs, raw = None, ""
            try:
                r = subprocess.run(bench_cmd, cwd=hc_dir, env=hashcat_env(),
                                    capture_output=True, text=True, timeout=60)
                raw = r.stdout + r.stderr
                m = self._SPEED_RE.search(raw)
                if m:
                    hs = parse_hashrate(m.group(2))
            except Exception as e:
                raw = str(e)
            self.after(0, lambda: self._show_estimate(keyspace, keyspace_desc, hs, raw))

        threading.Thread(target=worker, daemon=True).start()

    def _show_estimate(self, keyspace, keyspace_desc, hashrate, raw_output):
        self.estimate_btn.configure(state="normal")
        if not hashrate:
            self.gpu_status_var.set("GPU status: benchmark failed.")
            self.log.log(raw_output)
            messagebox.showerror("Benchmark failed",
                                  "Couldn't get a speed reading from hashcat's benchmark. "
                                  "See the log for the raw output.")
            return
        self.gpu_status_var.set(f"GPU status: benchmarked at {hashrate:,.0f} H/s")
        seconds = keyspace / hashrate
        msg = (f"Keyspace: {keyspace:,} candidates ({keyspace_desc})\n"
               f"Benchmarked speed: {hashrate:,.0f} H/s\n\n"
               f"Estimated time to try every candidate:\n{format_duration(seconds)}\n\n"
               f"(Could finish sooner if the password is found early; actual speed "
               f"may vary with GPU temperature/throttling.)")
        self.log.log(msg.replace("\n", "  "))
        messagebox.showinfo("Time Estimate", msg)

    def detect_devices(self):
        """Runs 'hashcat -I' to list backend devices and populates the
        dropdown as 'id: name'. Auto-selects the first device whose name
        contains 'NVIDIA'/'GeForce'/'RTX'/'GTX' so a discrete GPU is
        preferred over an Intel iGPU without the user having to know
        hashcat's device numbering.

        The same physical NVIDIA GPU is listed once per backend (CUDA and
        its OpenCL fallback), cross-referenced via '(Alias: #N)' in hashcat's
        own output - e.g. 'Backend Device ID #01 (Alias: #02)' for the CUDA
        entry and 'Backend Device ID #02 (Alias: #01)' for its OpenCL twin.
        Without resolving that, the RTX 3050 shows up twice in the list.
        We keep only the first-seen id for each alias pair (CUDA is always
        printed first by hashcat, so that's the faster one that gets kept)."""
        exe_abs, hc_dir = self._hashcat_paths()
        if exe_abs is None:
            return
        try:
            r = subprocess.run([exe_abs, "-I"], cwd=hc_dir, capture_output=True,
                                text=True, timeout=30, env=hashcat_env())
        except Exception as e:
            messagebox.showerror("Detect failed", str(e))
            return

        raw = []
        for chunk in re.split(r"Backend Device ID #", r.stdout)[1:]:
            id_match = re.match(r"(\d+)", chunk.strip())
            alias_match = re.search(r"Alias:\s*#(\d+)", chunk[:80])
            name_match = re.search(r"Name\.*:\s*(.+)", chunk)
            if id_match and name_match:
                raw.append((id_match.group(1), name_match.group(1).strip(),
                            alias_match.group(1) if alias_match else None))

        devices = []
        seen_ids = set()
        for did, name, alias in raw:
            if alias and alias in seen_ids:
                continue
            devices.append((did, name))
            seen_ids.add(did)

        if not devices:
            messagebox.showwarning("No devices found",
                                    "hashcat -I didn't report any backend devices. "
                                    "See the log for its raw output.")
            self.log.log(r.stdout)
            self.log.log(r.stderr)
            return

        labels = ["Auto (let hashcat choose)"] + [f"{did}: {name}" for did, name in devices]
        self.device_combo["values"] = labels

        nvidia_label = next(
            (lbl for lbl, (_, name) in zip(labels[1:], devices)
             if any(k in name.upper() for k in ("NVIDIA", "GEFORCE", "RTX", "GTX"))),
            None,
        )
        self.device_var.set(nvidia_label or labels[0])
        self.log.log("Detected devices:\n" + "\n".join(f"  {lbl}" for lbl in labels[1:]))
        if not nvidia_label:
            self.log.log("No NVIDIA device detected - check that the NVIDIA driver "
                          "(and CUDA, for the fastest backend) is installed.")

    def start_crack(self):
        exe_abs, hc_dir = self._hashcat_paths()
        if exe_abs is None:
            return
        hash_file = self.hash_entry.get().strip()
        out_file = self.out_entry.get().strip()
        if not hash_file or not os.path.isfile(hash_file):
            messagebox.showerror("Hash file not found", "Browse to a valid hash file.")
            return

        cmd = [exe_abs, "-m", "22000", os.path.abspath(hash_file)]
        if self.attack_mode.get() == "dict":
            wordlist = self.wordlist_entry.get().strip()
            if not wordlist or not os.path.isfile(wordlist):
                messagebox.showerror("Wordlist not found", "Browse to a valid wordlist.")
                return
            cmd += [os.path.abspath(wordlist)]
        else:
            mask = self.mask_entry.get().strip()
            if not mask:
                messagebox.showerror("Mask required",
                                      "Enter a mask, e.g. ?d?d?d?d?d?d?d?d?d?d for a 10-digit number "
                                      "(or click '10-digit phone').")
                return
            cmd += ["-a", "3", mask]

        device_sel = self.device_var.get().strip()
        if device_sel and not device_sel.startswith("Auto"):
            cmd += ["-d", device_sel.split(":", 1)[0].strip()]

        if out_file:
            cmd += ["-o", os.path.abspath(out_file)]
        extra = self.extra_entry.get().strip()
        if "--status" not in extra:
            cmd += ["--status", "--status-timer=5"]
        if extra:
            cmd += extra.split()

        self.log.clear()
        self.result_var.set("")
        self.gpu_status_var.set("GPU status: starting...")
        self.progress_var.set(0.0)
        self._last_progress = (0, 0, 0.0)
        self._last_eta = ("", "")
        self.progress_text_var.set("Progress: -- | Remaining: -- | Finishes: --")
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
                cwd=hc_dir, capture_output=True, text=True, timeout=60, env=hashcat_env(),
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

    _SPEED_RE = re.compile(r"Speed\.#(\d+)\.*:\s*([\d.,]+\s*\S?H/s)")
    _HWMON_RE = re.compile(r"Hardware\.Mon\.#(\d+)\.*:\s*(.+)")
    _PROGRESS_RE = re.compile(r"Progress\.*:\s*([\d,]+)/([\d,]+)\s*\(([\d.]+)%\)")
    _ETA_RE = re.compile(r"Time\.Estimated\.*:\s*(.+)")

    def _parse_gpu_status(self, line):
        """Turns hashcat's own status-block lines (which the log panel
        already shows verbatim, but easy to miss in the scroll) into the
        progress bar, an ETA/remaining-time line, and a short line
        confirming which device number is actually crunching - Hardware.
        Mon/Speed lines only ever appear for the device(s) actually running
        the attack, never for a device hashcat enumerated but skipped, so
        there's no ambiguity like there would be parsing the startup
        device banner. All of this only appears because start_crack()
        always adds --status --status-timer=5 - without it hashcat never
        prints these lines to a non-interactive (piped) process at all."""
        m = self._HWMON_RE.search(line)
        if m:
            self._status_queue.put(("gpu", f"Device #{m.group(1)} running - {m.group(2).strip()}"))
            return
        m = self._SPEED_RE.search(line)
        if m:
            self._status_queue.put(("gpu", f"Device #{m.group(1)} speed: {m.group(2)}"))
            return
        m = self._PROGRESS_RE.search(line)
        if m:
            done = int(m.group(1).replace(",", ""))
            total = int(m.group(2).replace(",", ""))
            pct = float(m.group(3))
            self._status_queue.put(("progress", (done, total, pct)))
            return
        m = self._ETA_RE.search(line)
        if m:
            text = m.group(1).strip()
            idx = text.find("(")
            if idx != -1 and text.endswith(")"):
                eta_date, remaining = text[:idx].strip(), text[idx + 1:-1].strip()
            else:
                eta_date, remaining = text, ""
            self._status_queue.put(("eta", (eta_date, remaining)))

    def _refresh_progress_text(self):
        done, total, pct = self._last_progress
        eta_date, remaining = self._last_eta
        text = f"Progress: {pct:.2f}%  ({done:,} / {total:,})"
        if remaining:
            text += f"  |  Remaining: {remaining}"
        if eta_date:
            text += f"  |  Finishes: {eta_date}"
        self.progress_text_var.set(text)

    def _drain_gpu_status(self):
        latest_gpu = None
        while True:
            try:
                kind, payload = self._status_queue.get_nowait()
            except queue.Empty:
                break
            if kind == "gpu":
                latest_gpu = payload
            elif kind == "progress":
                self._last_progress = payload
                self.progress_var.set(payload[2])
            elif kind == "eta":
                self._last_eta = payload
        if latest_gpu is not None:
            self.gpu_status_var.set(f"GPU status: {latest_gpu}")
        self._refresh_progress_text()
        self.after(300, self._drain_gpu_status)

    def _run_tracked(self, cmd, cwd, on_done):
        def worker():
            self.log.log(f"$ {' '.join(cmd)}   (cwd={cwd})")
            try:
                self._proc = subprocess.Popen(
                    cmd, cwd=cwd, env=hashcat_env(),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1,
                )
                for line in self._proc.stdout:
                    self.log.log(line)
                    self._parse_gpu_status(line)
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
        run_streaming(cmd, self.log, cwd=hc_dir, env=hashcat_env())

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

        ico_path = PHOTOS_DIR / "logo.ico"
        if ico_path.is_file():
            # .ico carries multiple resolutions - this is what Windows
            # actually uses for the taskbar icon, not iconphoto()'s PNG
            # (which mainly covers the title bar / Alt-Tab thumbnail and
            # only reliably reaches the taskbar on some Tk/Windows builds).
            try:
                self.iconbitmap(default=str(ico_path))
            except tk.TclError:
                pass

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

        notebook.add(ScrollableTab(notebook, FlashTab, port_var), text="1. Flash")
        notebook.add(ScrollableTab(notebook, CaptureTab, port_var), text="2. Capture")
        notebook.add(ScrollableTab(notebook, ConvertTab), text="3. Convert")
        notebook.add(ScrollableTab(notebook, InspectIsolateTab), text="4. Inspect & Isolate")
        notebook.add(ScrollableTab(notebook, CrackTab, cracked_var), text="5. Crack")
        notebook.add(ScrollableTab(notebook, ResultsTab, cracked_var), text="6. Results")


def main():
    if serial is None:
        print("Warning: pyserial is not installed. Run: pip install pyserial", file=sys.stderr)
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
