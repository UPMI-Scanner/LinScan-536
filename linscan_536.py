#!/usr/bin/env python3
"""
LinScan-536: Graphical interface, activity logger, and audio recorder
for Uniden BCD536HP digital scanners over serial and Wi-Fi RTSP interfaces.

Repository: https://github.com/UPMI-Scanner/LinScan-536
License: MIT
"""

import csv
import datetime
import glob
import json
import os
import queue
import re
import socket
import subprocess
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, simpledialog, ttk

import serial

BAUD_RATE = 115200


def clean_text_for_log(text: str) -> str:
    """Strip non-printable ASCII characters for clean UI rendering and CSV export."""
    return "".join(c for c in text if 0x20 <= ord(c) <= 0x7E).strip()


def clean_uniden_lcd(text: str) -> str:
    """Replace proprietary Uniden hardware LCD glyphs with spaces to maintain layout."""
    return "".join(c if 0x20 <= ord(c) <= 0x7E else " " for c in text)


def is_status_line(text: str) -> bool:
    """Identify and filter out scanner status banners, modes, and metadata."""
    clean_upper = text.upper().strip()
    if not clean_upper or len(clean_upper) <= 1:
        return True

    if clean_upper.startswith(("F0:", "S0:", "UID:", "UID ", "TGID:", "TGID ")):
        return True

    status_prefixes = (
        "SCAN", "SEARCH", "ID SEARCH", "ID SCAN", "LINK", "FIND",
        "FOR RECORD", "RECORD", "REPLAY", "HOLD", "AVOID", "PRIORITY"
    )
    if any(clean_upper.startswith(p) for p in status_prefixes):
        return True

    status_tokens = {
        "DATA", "DAT", "NFM", "FM", "AM", "FMN", "AUTO",
        "P25", "PT0", "PT1", "DMR", "NXDN"
    }
    return clean_upper in status_tokens


class ScrollCatcher:
    """
    Stitches scrolling LCD text strings across serial poll cycles.
    Maintains a 128-character buffer to prevent memory leaks.
    """

    def __init__(self, max_length: int = 128):
        self.full_text = ""
        self.last_seen = ""
        self.max_length = max_length

    def update(self, current: str) -> str:
        current = current.strip()

        if not current:
            self.full_text = ""
            self.last_seen = ""
            return ""

        if len(self.full_text) > self.max_length:
            self.last_seen = current
            return self.full_text

        if not self.full_text:
            self.full_text = self.last_seen = current
            return self.full_text

        if current == self.last_seen:
            return self.full_text

        prefix_len = 0
        for i in range(min(len(self.last_seen), len(current))):
            if self.last_seen[i] == current[i]:
                prefix_len += 1
            else:
                break

        last_rem = self.last_seen[prefix_len:]
        curr_rem = current[prefix_len:]

        if len(last_rem) > 1 and len(curr_rem) > 1 and last_rem[1:] == curr_rem[:-1]:
            self.full_text += curr_rem[-1]
            self.last_seen = current
            return self.full_text

        if len(last_rem) > 2 and len(curr_rem) > 2 and last_rem[2:] == curr_rem[:-2]:
            self.full_text += curr_rem[-2:]
            self.last_seen = current
            return self.full_text

        if self.full_text.startswith(current):
            self.last_seen = current
            return self.full_text

        self.full_text = self.last_seen = current
        return self.full_text


class SerialManager(threading.Thread):
    """
    Dedicated background serial worker thread.
    Handles all port discovery, polling, reading, and writing off the main GUI thread.
    """

    def __init__(self, data_queue: queue.Queue):
        super().__init__(daemon=True)
        self.data_queue = data_queue
        self.cmd_queue = queue.Queue()
        self.running = True
        self.ser = None
        self.serial_buffer = b""

    def send_cmd(self, cmd: bytes):
        """Enqueue a command to be sent asynchronously to the scanner."""
        self.cmd_queue.put(cmd)

    def run(self):
        poll_timer = 0.0
        hw_timer = 0.0
        poll_cycle = 0

        while self.running:
            # 1. Connection check / Reconnect
            if not self.ser or not self.ser.is_open:
                ports = sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"))
                if not ports:
                    self.data_queue.put(("STATUS", ("NO USB DETECTED", "#FF0033")))
                    time.sleep(1.5)
                    continue

                for p in ports:
                    try:
                        self.ser = serial.Serial(p, BAUD_RATE, timeout=0.1, write_timeout=0.2)
                        self.serial_buffer = b""
                        self.data_queue.put(("STATUS", (f"CONNECTED ({os.path.basename(p)})", "#39FF14")))
                        now = datetime.datetime.now()
                        dst_flag = 1 if time.localtime().tm_isdst > 0 else 0
                        dtm_cmd = f"DTM,{dst_flag},{now.strftime('%Y,%m,%d,%H,%M,%S')}\r".encode("ascii")
                        self.ser.write(dtm_cmd)
                        break
                    except Exception:
                        self.ser = None

                if not self.ser:
                    time.sleep(1.5)
                    continue

            # 2. Process outgoing commands from GUI
            while not self.cmd_queue.empty():
                try:
                    cmd = self.cmd_queue.get_nowait()
                    if self.ser and self.ser.is_open:
                        self.ser.write(cmd)
                except Exception:
                    self._close_port()
                    break

            if not self.ser or not self.ser.is_open:
                continue

            now = time.time()

            # 3. Scheduled polling
            if now - poll_timer >= 0.15:
                poll_timer = now
                poll_cycle += 1
                try:
                    if poll_cycle % 15 == 5:
                        self.ser.write(b"VOL\r")
                    elif poll_cycle % 15 == 10:
                        self.ser.write(b"SQL\r")
                    else:
                        self.ser.write(b"STS\r")
                except Exception:
                    self._close_port()
                    continue

            if now - hw_timer >= 2.0:
                hw_timer = now
                try:
                    self.ser.write(b"VOL\rSQL\rCLC\r")
                except Exception:
                    self._close_port()
                    continue

            # 4. Read incoming serial stream
            try:
                if self.ser.in_waiting:
                    chunk = self.ser.read(self.ser.in_waiting)
                    self.serial_buffer += chunk

                    if len(self.serial_buffer) > 4096:
                        self.serial_buffer = self.serial_buffer[-1024:]

                    while b"\r" in self.serial_buffer:
                        raw_line, self.serial_buffer = self.serial_buffer.split(b"\r", 1)
                        line = raw_line.decode("latin-1", errors="ignore").strip()
                        if line:
                            self.data_queue.put(("RAW", line))
            except Exception:
                self._close_port()

            time.sleep(0.015)

    def _close_port(self):
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None
        self.data_queue.put(("STATUS", ("DISCONNECTED", "#FF0033")))

    def stop(self):
        self.running = False
        self._close_port()


class USBRecordingEngine(threading.Thread):
    """Captures and filters audio via local ALSA/PulseAudio inputs."""

    def __init__(self, mp3_file: str):
        super().__init__(daemon=True)
        self.mp3_file = mp3_file
        self.running = True
        self.ffmpeg_proc = None
        self.start_time = datetime.datetime.now()

    def run(self):
        vox_filter = "silenceremove=start_periods=1:start_duration=0:start_threshold=-45dB:stop_periods=-1:stop_duration=2:stop_threshold=-45dB"
        norm_filter = "loudnorm=I=-16:TP=-1.5:LRA=11"

        ffmpeg_cmd = [
            "ffmpeg", "-hide_banner", "-loglevel", "warning", "-stats", "-y",
            "-f", "pulse", "-i", "default",
            "-af", f"aresample=async=1,{vox_filter},{norm_filter}",
            "-c:a", "libmp3lame", "-b:a", "64k", self.mp3_file
        ]

        try:
            self.ffmpeg_proc = subprocess.Popen(
                ffmpeg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            self._monitor_recording()
        except OSError:
            pass

    def _monitor_recording(self):
        if not self.ffmpeg_proc or not self.ffmpeg_proc.stderr:
            return
        buf = ""
        try:
            while self.running:
                chunk = self.ffmpeg_proc.stderr.read(64)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", errors="ignore")
                while "\r" in buf or "\n" in buf:
                    parts = re.split(r"[\r\n]", buf, maxsplit=1)
                    buf = parts[1] if len(parts) > 1 else ""
        except OSError:
            pass

    def stop(self):
        self.running = False
        if self.ffmpeg_proc:
            try:
                self.ffmpeg_proc.terminate()
                self.ffmpeg_proc.wait(timeout=2)
            except Exception:
                try:
                    self.ffmpeg_proc.kill()
                except Exception:
                    pass
            self.ffmpeg_proc = None
        self.cleanup()

    def cleanup(self):
        if os.path.exists(self.mp3_file):
            try:
                if os.path.getsize(self.mp3_file) < 20000:
                    os.remove(self.mp3_file)
                else:
                    new_name = f"Session_USB_{self.start_time.strftime('%Y-%m-%d_%I-%M-%S%p')}_to_{datetime.datetime.now().strftime('%I-%M-%S%p')}.mp3"
                    new_path = os.path.join(os.path.dirname(self.mp3_file), new_name)
                    if os.path.exists(new_path):
                        os.remove(new_path)
                    os.rename(self.mp3_file, new_path)
            except OSError:
                pass


class RTSPAudioEngine(threading.Thread):
    """Extracts raw digital audio streams from the Uniden Wi-Fi dongle via RTSP."""

    def __init__(self, scanner_ip: str, mp3_file: str):
        super().__init__(daemon=True)
        self.ip = scanner_ip
        self.mp3_file = mp3_file
        self.running = True
        self.tcp_sock = None
        self.udp_sock = None
        self.ffmpeg_proc = None
        self.start_time = datetime.datetime.now()

    def run(self):
        audio_filter = "volume=3.0,silenceremove=start_periods=1:start_duration=0.05:start_threshold=-42dB:stop_periods=-1:stop_duration=1.0:stop_threshold=-42dB,loudnorm=I=-16:TP=-1.5:LRA=11"

        ffmpeg_cmd = [
            "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "warning", "-stats", "-y",
            "-f", "mulaw", "-ar", "8000", "-ac", "1", "-i", "pipe:0",
            "-af", audio_filter, "-c:a", "libmp3lame", "-b:a", "64k", self.mp3_file
        ]
        try:
            self.ffmpeg_proc = subprocess.Popen(
                ffmpeg_cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
        except OSError:
            return

        while self.running:
            try:
                self.connect_and_stream()
            except Exception:
                if self.running:
                    self.close_sockets()
                    time.sleep(2)
        self.cleanup()

    def connect_and_stream(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(("0.0.0.0", 0))
        rtp_port = self.udp_sock.getsockname()[1]
        rtcp_port = rtp_port + 1
        self.udp_sock.settimeout(2.0)

        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.settimeout(5.0)
        self.tcp_sock.connect((self.ip, 554))

        cseq = 1
        reqs = [
            f"OPTIONS rtsp://{self.ip}/au:scanner.au RTSP/1.0\r\nCSeq: {{}}\r\nUser-Agent: LinScan\r\n\r\n",
            f"DESCRIBE rtsp://{self.ip}/au:scanner.au RTSP/1.0\r\nCSeq: {{}}\r\nUser-Agent: LinScan\r\nAccept: application/sdp\r\n\r\n",
            f"SETUP rtsp://{self.ip}/au:scanner.au/trackID=1 RTSP/1.0\r\nCSeq: {{}}\r\nUser-Agent: LinScan\r\nTransport: RTP/AVP;unicast;client_port={rtp_port}-{rtcp_port}\r\n\r\n"
        ]
        for req in reqs[:2]:
            self.tcp_sock.sendall(req.format(cseq).encode())
            self.tcp_sock.recv(1024)
            cseq += 1

        self.tcp_sock.sendall(reqs[2].format(cseq).encode())
        resp = self.tcp_sock.recv(1024).decode(errors="ignore")
        cseq += 1

        session_id = (re.search(r"Session:\s*([^\r\n;]+)", resp, re.IGNORECASE) or [None, ""])[1].strip()
        server_port = int((re.search(r"server_port=\s*([0-9]+)", resp, re.IGNORECASE) or [None, 5004])[1])

        req = f"PLAY rtsp://{self.ip}/au:scanner.au/ RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: LinScan\r\nSession: {session_id}\r\nRange: npt=0.000-\r\n\r\n"
        self.tcp_sock.sendall(req.encode())
        self.tcp_sock.recv(1024)
        cseq += 1

        for p in [server_port, 5000, 5004, 5006]:
            try:
                self.udp_sock.sendto(b"\x80\x00\x00\x00", (self.ip, p))
            except OSError:
                pass

        last_ping = time.time()
        while self.running:
            if time.time() - last_ping > 10.0:
                try:
                    self.tcp_sock.sendall(f"OPTIONS rtsp://{self.ip}/au:scanner.au RTSP/1.0\r\nCSeq: {cseq}\r\nSession: {session_id}\r\nUser-Agent: LinScan\r\n\r\n".encode())
                    self.tcp_sock.recv(512)
                    cseq += 1
                except OSError:
                    pass
                last_ping = time.time()

            try:
                data, _ = self.udp_sock.recvfrom(2048)
                if len(data) > 12 and self.ffmpeg_proc and self.ffmpeg_proc.stdin:
                    try:
                        self.ffmpeg_proc.stdin.write(data[12:])
                        self.ffmpeg_proc.stdin.flush()
                    except (BrokenPipeError, OSError):
                        break
            except socket.timeout:
                continue

        self.close_sockets()

    def stop(self):
        self.running = False
        if self.tcp_sock:
            try:
                self.tcp_sock.sendall(f"TEARDOWN rtsp://{self.ip}/au:scanner.au/ RTSP/1.0\r\nCSeq: 99\r\nUser-Agent: LinScan\r\n\r\n".encode())
            except OSError:
                pass
        self.close_sockets()

    def close_sockets(self):
        for sock in (self.tcp_sock, self.udp_sock):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        self.tcp_sock = self.udp_sock = None

    def cleanup(self):
        self.close_sockets()
        if self.ffmpeg_proc:
            try:
                if self.ffmpeg_proc.stdin:
                    self.ffmpeg_proc.stdin.close()
                self.ffmpeg_proc.wait(timeout=2)
            except Exception:
                try:
                    self.ffmpeg_proc.kill()
                except Exception:
                    pass
            self.ffmpeg_proc = None

        if os.path.exists(self.mp3_file):
            try:
                if os.path.getsize(self.mp3_file) < 20000:
                    os.remove(self.mp3_file)
                else:
                    new_name = f"Session_VOX_{self.start_time.strftime('%Y-%m-%d_%I-%M-%S%p')}_to_{datetime.datetime.now().strftime('%I-%M-%S%p')}.mp3"
                    new_path = os.path.join(os.path.dirname(self.mp3_file), new_name)
                    if os.path.exists(new_path):
                        os.remove(new_path)
                    os.rename(self.mp3_file, new_path)
            except OSError:
                pass


class VirtualScanner(tk.Tk):
    """Main graphical user interface for LinScan."""

    def __init__(self):
        super().__init__()
        self.title("LinScan-536")
        self.geometry("1100x780")
        self.minsize(1050, 650)
        self.configure(bg="#050505")

        self.lcd_font = tkfont.Font(family="Courier", size=17, weight="bold")

        self.rtsp_engine = None
        self.usb_engine = None

        self.active_call = False
        self.record_enabled = False
        self.usb_record_enabled = False
        self._ignore_slider_events = False

        self.current_uid = ""
        self.current_tgid = ""
        self.scanner_ip = ""
        self.last_key_time = 0.0

        self.catchers = [ScrollCatcher() for _ in range(16)]
        self.log_sys = ScrollCatcher()
        self.log_dept = ScrollCatcher()
        self.log_chan = ScrollCatcher()

        self.tg_hits = {}
        self.call_times = {}
        self.current_call_start = None

        self.lcd_colors = ["#C0C0C0", "#FFA500", "#39FF14", "#00FFFF", "#FFB6C1", "#ADD8E6"]
        self.current_color_idx = 0

        self.config_dir = os.path.expanduser("~/.config/linscan")
        self.config_file = os.path.join(self.config_dir, "config.json")

        self._last_sig = ""
        self._last_sig_color = ""
        self._last_scan_state = None
        self._last_bg_size = None

        self.load_config()
        self._build_ui()

        self.serial_queue = queue.Queue()
        self.serial_manager = SerialManager(self.serial_queue)
        self.serial_manager.start()

        self.bind_all("<Key>", self.handle_keypress)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.process_serial_queue()
        
        # Ensure correct background color is applied immediately on boot
        self.update_idletasks()
        self.draw_background()

    def load_config(self):
        """Load configuration from JSON, explicitly logging any failures."""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    self.scanner_ip = config.get("scanner_ip", "")
                    
                    # Strictly cast to int and ensure it is within the bounds of our color list
                    loaded_color = int(config.get("lcd_color_idx", 0))
                    self.current_color_idx = loaded_color % len(self.lcd_colors)
                    
                    print(f"LinScan Config Loaded -> IP: '{self.scanner_ip}', LCD Color Index: {self.current_color_idx}")
            except Exception as e:
                print(f"LinScan Warning: Failed to parse {self.config_file}: {e}")
        else:
            print("LinScan: No existing config.json found. Checking for legacy ip txt file...")
            legacy_file = os.path.expanduser("~/linscan_ip.txt")
            if os.path.exists(legacy_file):
                try:
                    with open(legacy_file, "r", encoding="utf-8") as f:
                        self.scanner_ip = f.read().strip()
                    os.remove(legacy_file)
                    print(f"LinScan: Migrated legacy IP {self.scanner_ip} and removed txt file.")
                except Exception as e:
                    print(f"LinScan Warning: Legacy file migration failed: {e}")
            self.save_config()

    def save_config(self):
        """Save settings persistently to JSON."""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            config = {
                "scanner_ip": self.scanner_ip,
                "lcd_color_idx": self.current_color_idx
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
            print(f"LinScan Config Saved -> IP: '{self.scanner_ip}', LCD Color Index: {self.current_color_idx}")
        except Exception as e:
            print(f"LinScan Error: Failed to write to {self.config_file}: {e}")

    def _build_ui(self):
        """Construct the Tkinter interface components."""
        self.faceplate = tk.Frame(self, bg="#1a1a1a", bd=4, relief=tk.RAISED)
        self.faceplate.pack(fill=tk.X, padx=15, pady=15)

        self.software_panel = tk.Frame(self, bg="#050505")
        self.software_panel.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        self.vol_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.vol_panel.pack(side=tk.LEFT, fill=tk.Y, padx=20, pady=20)

        for name, to_val, cmd_func in [("VOL", 29, self.send_volume), ("SQL", 19, self.send_squelch)]:
            sub = tk.Frame(self.vol_panel, bg="#1a1a1a")
            sub.pack(side=tk.LEFT, padx=5)
            tk.Label(sub, text=name, fg="#888888", bg="#1a1a1a", font=("Arial", 11, "bold")).pack(pady=(0, 5))
            slider = tk.Scale(
                sub, from_=to_val, to=0, orient=tk.VERTICAL, bg="#111111",
                fg="#39FF14" if name == "VOL" else "#00FFFF",
                troughcolor="#050505", bd=1, highlightthickness=0, relief=tk.SUNKEN,
                activebackground="#2a2a2a", command=cmd_func, length=180
            )
            slider.pack(fill=tk.Y, expand=True)
            if name == "VOL":
                self.vol_slider = slider
            else:
                self.sql_slider = slider

        self.keypad_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.keypad_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=20, pady=20)

        self.center_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.center_panel.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.knob = tk.Canvas(self.keypad_panel, width=100, height=100, bg="#1a1a1a", highlightthickness=0, cursor="hand2")
        self.knob.pack(pady=(0, 15))
        self.knob.create_oval(5, 5, 95, 95, fill="#222222", outline="#111111")
        self.knob.create_oval(10, 10, 90, 90, fill="#777777", outline="#555555")
        self.knob.create_oval(20, 20, 80, 80, fill="#AAAAAA", outline="")
        self.knob.create_oval(30, 30, 70, 70, fill="#DDDDDD", outline="#888888")
        self.knob.create_text(25, 50, text="◀", fill="#111111", font=("Arial", 14, "bold"))
        self.knob.create_text(75, 50, text="▶", fill="#111111", font=("Arial", 14, "bold"))
        self.knob.create_text(50, 50, text="PUSH\n[E]", fill="#111111", font=("Arial", 8, "bold"), justify="center")

        self.knob.bind("<Button-1>", lambda e: self.send_key("<") if e.x < 35 else (self.send_key(">") if e.x > 65 else self.send_key("E")))
        self.knob.bind("<Button-4>", lambda e: self.send_key("<"))
        self.knob.bind("<Button-5>", lambda e: self.send_key(">"))
        self.knob.bind("<MouseWheel>", lambda e: self.send_key("<") if e.delta > 0 else self.send_key(">"))

        btn_style = {
            "font": ("Arial", 10, "bold"), "bg": "#111111", "fg": "#FFFFFF",
            "bd": 1, "activebackground": "#333333", "activeforeground": "#FFFFFF", "cursor": "hand2"
        }
        keypad_rows = [
            [("RANGE", "R"), ("CLOSE CALL", "Q")],
            [("MENU", "M"), ("REPLAY", "Y")],
            [("1", "1"), ("2", "2"), ("3", "3")],
            [("4", "4"), ("5", "5"), ("6", "6")],
            [("7", "7"), ("8", "8"), ("9", "9")],
            [(". / NO", "."), ("0", "0"), ("E / YES", "E")]
        ]
        for row in keypad_rows:
            row_f = tk.Frame(self.keypad_panel, bg="#1a1a1a")
            row_f.pack(fill=tk.X, pady=3)
            for text, key_code in row:
                tk.Button(
                    row_f, text=text, width=12 if len(row) == 2 else 7, height=1,
                    command=lambda k=key_code: self.send_key(k), **btn_style
                ).pack(side=tk.LEFT, padx=3, expand=True)

        self.lcd_header = tk.Frame(self.center_panel, bg="#1a1a1a")
        self.lcd_header.pack(fill=tk.X, padx=20, pady=(0, 5))

        tk.Label(self.lcd_header, text="UNIDEN SCANNER", fg="#AAAAAA", bg="#1a1a1a", font=("Arial", 14, "bold")).pack(side=tk.LEFT)
        self.status_label = tk.Label(self.lcd_header, text="CONNECTING...", fg="#39FF14", bg="#1a1a1a", font=("Courier", 14, "bold"))
        self.status_label.pack(side=tk.RIGHT)
        self.sig_label = tk.Label(self.lcd_header, text="SIG: \u25a1 \u25a1 \u25a1 \u25a1 \u25a1", fg="#555555", bg="#1a1a1a", font=("Courier", 14, "bold"))
        self.sig_label.pack(side=tk.RIGHT, padx=15)
        self.cc_indicator = tk.Label(self.lcd_header, text="\u2B24 CC: OFF", fg="#555555", bg="#1a1a1a", font=("Arial", 14, "bold"))
        self.cc_indicator.pack(side=tk.RIGHT, padx=15)

        self.bezel = tk.Frame(self.center_panel, bg="#050505", highlightthickness=2, highlightbackground="#333333")
        self.bezel.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)
        self.lcd_canvas = tk.Canvas(self.bezel, bg="#050505", highlightthickness=0, cursor="hand2")
        self.lcd_canvas.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        self.lcd_texts = []
        for i in range(6):
            t = self.lcd_canvas.create_text(25, 20 + (i * 34), text="", fill="#000000", font=self.lcd_font, anchor="nw")
            self.lcd_texts.append(t)

        self.lcd_canvas.bind("<Configure>", self.draw_background)
        self.lcd_canvas.bind("<Button-4>", lambda e: self.send_key("<"))
        self.lcd_canvas.bind("<Button-5>", lambda e: self.send_key(">"))
        self.lcd_canvas.bind("<MouseWheel>", lambda e: self.send_key("<") if e.delta > 0 else self.send_key(">"))

        soft_f = tk.Frame(self.center_panel, bg="#1a1a1a")
        soft_f.pack(fill=tk.X, padx=20, pady=(10, 5))
        soft_keys = [("SYS", "A"), ("DEPT", "B"), ("CH", "C"), ("AVOID", "L"), ("ZIP", "Z"), ("SERV", "T")]
        for text, key_code in soft_keys:
            tk.Button(
                soft_f, text=text, height=2,
                command=lambda k=key_code: self.send_key(k), **btn_style
            ).pack(side=tk.LEFT, padx=4, expand=True, fill=tk.X)

        self.log_ctrl_frame = tk.Frame(self.software_panel, bg="#050505")
        self.log_ctrl_frame.pack(fill=tk.X, pady=(0, 5))
        tk.Label(
            self.log_ctrl_frame, text="ACTIVITY TABLE (Double-click row to Hold Channel)",
            fg="#00FFFF", bg="#050505", font=("Courier", 11, "bold")
        ).pack(side=tk.LEFT)

        btn_config = {"font": ("Arial", 9, "bold"), "bg": "#1a1a1a", "bd": 0, "cursor": "hand2"}
        for txt, fg_col, cmd in [
            ("CLEAR LOG", "#00FFFF", self.clear_log),
            ("EXPORT CSV", "#39FF14", self.export_csv),
            ("FOLDER", "#00FFFF", self.open_audio_folder)
        ]:
            tk.Button(self.log_ctrl_frame, text=txt, fg=fg_col, command=cmd, **btn_config).pack(side=tk.RIGHT, padx=4)

        self.ip_btn = tk.Button(self.log_ctrl_frame, text="SET IP", fg="#FFFF00", command=self.set_ip, **btn_config)
        self.ip_btn.pack(side=tk.RIGHT, padx=4)

        self.wifi_rec_btn = tk.Button(self.log_ctrl_frame, text="○ WIFI REC", fg="#888888", command=self.toggle_wifi_record, **btn_config)
        self.wifi_rec_btn.pack(side=tk.RIGHT, padx=4)

        self.usb_rec_btn = tk.Button(self.log_ctrl_frame, text="○ USB REC", fg="#888888", command=self.toggle_usb_record, **btn_config)
        self.usb_rec_btn.pack(side=tk.RIGHT, padx=4)

        self.sd_rec_btn = tk.Button(self.log_ctrl_frame, text="SD REC", fg="#FF0000", command=self.toggle_sd_record, **btn_config)
        self.sd_rec_btn.pack(side=tk.RIGHT, padx=4)

        self.color_btn = tk.Button(self.log_ctrl_frame, text="LCD COLOR", fg="#FFFFFF", command=self.cycle_lcd_color, **btn_config)
        self.color_btn.pack(side=tk.RIGHT, padx=4)

        style = ttk.Style()
        style.theme_use("default")

        style.configure(
            "Treeview", background="#FFFFFF", foreground="#000000",
            fieldbackground="#FFFFFF", rowheight=32, font=("Arial", 12, "bold")
        )
        style.configure("Treeview.Heading", background="#D0D0D0", foreground="#000000", font=("Arial", 11, "bold"), relief="raised")
        style.map("Treeview", background=[("selected", "#0055FF")], foreground=[("selected", "#FFFFFF")])

        self.tree_columns = ("time", "sys", "dept", "chan", "tgid", "uid", "hits", "call_time")
        self.log_tree = ttk.Treeview(self.software_panel, columns=self.tree_columns, show="headings", selectmode="browse")

        cols_config = [
            ("time", "LAST SEEN", 110, "center"),
            ("sys", "SYSTEM", 185, "w"),
            ("dept", "DEPARTMENT", 185, "w"),
            ("chan", "CHANNEL", 185, "w"),
            ("tgid", "TGID", 80, "center"),
            ("uid", "LAST UID", 100, "center"),
            ("hits", "HITS", 60, "center"),
            ("call_time", "TIME", 80, "center")
        ]
        for col_id, heading, width, anchor in cols_config:
            self.log_tree.heading(col_id, text=heading)
            self.log_tree.column(col_id, width=width, anchor=anchor)

        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar = tk.Scrollbar(self.software_panel, command=self.log_tree.yview, bg="#1a1a1a", troughcolor="#050505", bd=0)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_tree.config(yscrollcommand=self.scrollbar.set)

        self.log_tree.tag_configure("law", background="#E6F0FA", foreground="#000000")
        self.log_tree.tag_configure("fire", background="#FAE6E6", foreground="#000000")
        self.log_tree.tag_configure("ems", background="#E6FAE6", foreground="#000000")
        self.log_tree.tag_configure("works", background="#FAF0E6", foreground="#000000")
        self.log_tree.tag_configure("dnr", background="#E6F5EA", foreground="#000000")
        self.log_tree.tag_configure("default", background="#FFFFFF", foreground="#000000")

        self.log_tree.bind("<Double-1>", lambda e: self.send_key("C") if self.log_tree.selection() else None)

    def draw_background(self, event=None):
        width = self.lcd_canvas.winfo_width()
        height = self.lcd_canvas.winfo_height()
        if width < 50 or height < 50:
            return

        if self._last_bg_size == (width, height, self.current_color_idx):
            return
        self._last_bg_size = (width, height, self.current_color_idx)

        self.lcd_canvas.delete("bg")
        r, c = 20, self.lcd_colors[self.current_color_idx]
        for coords in [
            (0, 0, 2 * r, 2 * r),
            (width - 2 * r, 0, width, 2 * r),
            (0, height - 2 * r, 2 * r, height),
            (width - 2 * r, height - 2 * r, width, height)
        ]:
            self.lcd_canvas.create_oval(*coords, fill=c, outline=c, tags="bg")
        self.lcd_canvas.create_rectangle(r, 0, width - r, height, fill=c, outline=c, tags="bg")
        self.lcd_canvas.create_rectangle(0, r, width, height - r, fill=c, outline=c, tags="bg")
        self.lcd_canvas.tag_lower("bg")

    def cycle_lcd_color(self):
        self.current_color_idx = (self.current_color_idx + 1) % len(self.lcd_colors)
        self.save_config()
        self.draw_background()

    def handle_keypress(self, event):
        sym = event.keysym
        key = event.char.lower()
        if sym in ("Up", "Left"):
            self.send_key("<")
        elif sym in ("Down", "Right"):
            self.send_key(">")
        elif sym in ("Return", "KP_Enter"):
            self.send_key("E")
        elif sym == "Escape":
            self.send_key("L")
        elif sym == "space":
            self.send_key("C")

        key_map = {
            "a": "A", "b": "B", "c": "C", "m": "M", "y": "Y", "s": "T",
            "t": "T", "z": "Z", "r": "R", "q": "Q", "l": "L", "f": "F", "e": "E"
        }
        if key in key_map:
            self.send_key(key_map[key])
        elif key in "0123456789.":
            self.send_key(key)

    def open_audio_folder(self):
        audio_dir = os.path.expanduser("~/LinScan_Audio")
        os.makedirs(audio_dir, exist_ok=True)
        subprocess.Popen(["xdg-open", audio_dir])

    def export_csv(self):
        items = self.log_tree.get_children()
        if not items:
            return
        default_name = f"LinScan_Log_{datetime.datetime.now().strftime('%Y-%m-%d_%I-%M-%S%p')}.csv"
        out_path = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile=default_name, filetypes=[("CSV Files", "*.csv")]
        )
        if out_path:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Last Seen", "System", "Department", "Channel", "TGID", "Last UID", "Hits", "Call Time"])
                for item in items:
                    writer.writerow(self.log_tree.item(item)["values"])

    def set_ip(self):
        new_ip = simpledialog.askstring(
            "Scanner IP", "Enter Uniden Wi-Fi IP Address:\n(e.g., 192.168.1.15)",
            initialvalue=self.scanner_ip, parent=self
        )
        if new_ip and new_ip.strip():
            self.scanner_ip = new_ip.strip()
            self.save_config()

    def toggle_sd_record(self):
        self.serial_manager.send_cmd(b"KEY,F,P\r")
        self.after(300, lambda: self.serial_manager.send_cmd(b"KEY,Y,P\r"))

    def toggle_usb_record(self):
        self.usb_record_enabled = not self.usb_record_enabled
        if self.usb_record_enabled:
            self.usb_rec_btn.config(text="● USB REC", fg="#FF0000")
            os.makedirs(os.path.expanduser("~/LinScan_Audio"), exist_ok=True)
            mp3_file = os.path.expanduser(f"~/LinScan_Audio/Session_USB_{datetime.datetime.now().strftime('%Y-%m-%d_%I-%M-%S%p')}.mp3")
            self.usb_engine = USBRecordingEngine(mp3_file)
            self.usb_engine.start()
        else:
            self.usb_rec_btn.config(text="○ USB REC", fg="#888888")
            if self.usb_engine:
                self.usb_engine.stop()
                self.usb_engine = None

    def toggle_wifi_record(self):
        if not self.scanner_ip:
            self.set_ip()
            if not self.scanner_ip:
                return

        self.record_enabled = not self.record_enabled
        if self.record_enabled:
            self.wifi_rec_btn.config(text="● WIFI REC", fg="#FF0000")
            os.makedirs(os.path.expanduser("~/LinScan_Audio"), exist_ok=True)
            vox_file = os.path.expanduser(f"~/LinScan_Audio/Session_VOX_{datetime.datetime.now().strftime('%Y-%m-%d_%I-%M-%S%p')}.mp3")
            self.rtsp_engine = RTSPAudioEngine(self.scanner_ip, vox_file)
            self.rtsp_engine.start()
        else:
            self.wifi_rec_btn.config(text="○ WIFI REC", fg="#888888")
            if self.rtsp_engine:
                self.rtsp_engine.stop()
                self.rtsp_engine = None

    def commit_log(self):
        """Finalize transmission data and insert a validated row into the Activity GUI table."""
        sys_final = clean_text_for_log(self.log_sys.full_text).strip()
        dept_final = clean_text_for_log(self.log_dept.full_text).strip()
        chan_final = clean_text_for_log(self.log_chan.full_text).strip()
        uid_final = self.current_uid.strip()
        tgid_final = self.current_tgid.strip()
        call_start = self.current_call_start

        self.active_call = False
        self.current_uid = ""
        self.current_tgid = ""
        self.current_call_start = None
        self.log_sys = ScrollCatcher()
        self.log_dept = ScrollCatcher()
        self.log_chan = ScrollCatcher()

        if not chan_final or is_status_line(chan_final):
            if not tgid_final:
                return
            chan_final = f"TGID {tgid_final}"

        if is_status_line(sys_final):
            sys_final = ""
        if is_status_line(dept_final):
            dept_final = ""

        tg_key = tgid_final if tgid_final else f"{dept_final}_{chan_final}" if dept_final else chan_final

        elapsed = 0.0
        if call_start is not None:
            elapsed = time.time() - call_start
        self.call_times[tg_key] = self.call_times.get(tg_key, 0.0) + elapsed
        self.tg_hits[tg_key] = self.tg_hits.get(tg_key, 0) + 1

        total_sec = int(self.call_times.get(tg_key, 0))
        mins, secs = divmod(total_sec, 60)
        hours, mins = divmod(mins, 60)
        time_str = f"{hours:02d}:{mins:02d}:{secs:02d}" if hours > 0 else f"{mins:02d}:{secs:02d}"

        now_str = datetime.datetime.now().strftime("%I:%M:%S %p")

        if self.log_tree.exists(tg_key):
            old_vals = self.log_tree.item(tg_key, "values")
            if not uid_final and len(old_vals) > 5 and old_vals[5]:
                uid_final = old_vals[5]
            if not tgid_final and len(old_vals) > 4 and old_vals[4]:
                tgid_final = old_vals[4]

        row_vals = (now_str, sys_final, dept_final, chan_final, tgid_final, uid_final, self.tg_hits[tg_key], time_str)

        row_tag = "default"
        combo_text = f"{dept_final} {chan_final}".upper()

        if any(x in combo_text for x in ("POLICE", "LAW", "SHERIFF", "STATE POLICE", "POST 81", "MSP")):
            row_tag = "law"
        elif "FIRE" in combo_text:
            row_tag = "fire"
        elif any(x in combo_text for x in ("EMS", "AMBULANCE", "HOSPITAL", "MEDICAL", "FIRST RESPONDERS")):
            row_tag = "ems"
        elif any(x in combo_text for x in ("ROAD", "PUBLIC WORKS", "DPW", "COMMISSION")):
            row_tag = "works"
        elif any(x in combo_text for x in ("NATURAL RES", "PARK", "DNR", "FOREST", "FISH AND WILDLIFE")):
            row_tag = "dnr"

        try:
            if self.log_tree.exists(tg_key):
                self.log_tree.item(tg_key, values=row_vals, tags=(row_tag,))
                self.log_tree.move(tg_key, "", 0)
            else:
                self.log_tree.insert("", 0, iid=tg_key, values=row_vals, tags=(row_tag,))
        except Exception:
            try:
                self.log_tree.insert("", 0, values=row_vals, tags=(row_tag,))
            except Exception:
                pass

    def on_closing(self):
        # Ensure configurations are saved upon window close
        self.save_config()
        self.record_enabled = False
        self.usb_record_enabled = False
        if self.rtsp_engine:
            self.rtsp_engine.stop()
        if self.usb_engine:
            self.usb_engine.stop()
        if self.serial_manager:
            self.serial_manager.stop()
        self.destroy()

    def clear_log(self):
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        self.tg_hits.clear()
        self.call_times.clear()

    def send_key(self, key_code: str):
        now = time.time()
        if now - self.last_key_time < 0.1:
            return
        self.last_key_time = now
        self.serial_manager.send_cmd(f"KEY,{key_code},P\r".encode("ascii"))

    def send_volume(self, val):
        if getattr(self, "_ignore_slider_events", False):
            return
        self.serial_manager.send_cmd(f"VOL,{int(val):02d}\r".encode("ascii"))

    def send_squelch(self, val):
        if getattr(self, "_ignore_slider_events", False):
            return
        self.serial_manager.send_cmd(f"SQL,{int(val):02d}\r".encode("ascii"))

    def process_serial_queue(self):
        """Consume messages from the background serial manager thread."""
        latest_sts = None

        while not self.serial_queue.empty():
            try:
                item = self.serial_queue.get_nowait()
                msg_type = item[0]

                if msg_type == "STATUS":
                    status_tuple = item[1]
                    text, color = status_tuple[0], status_tuple[1]
                    self.status_label.config(text=text, fg=color)
                elif msg_type == "RAW":
                    line = item[1]
                    if line.startswith("STS,"):
                        latest_sts = line
                    elif line.startswith("VOL,"):
                        try:
                            self._ignore_slider_events = True
                            self.vol_slider.set(int(line.split(",")[1]))
                            self._ignore_slider_events = False
                        except Exception:
                            pass
                    elif line.startswith("SQL,"):
                        try:
                            self._ignore_slider_events = True
                            self.sql_slider.set(int(line.split(",")[1]))
                            self._ignore_slider_events = False
                        except Exception:
                            pass
                    elif line.startswith("CLC,"):
                        try:
                            mode = line.split(",")[1].strip()
                            if mode == "0":
                                self.cc_indicator.config(text="\u2B24 CC: OFF", fg="#555555")
                            elif mode == "1":
                                self.cc_indicator.config(text="\u2B24 CC: PRI", fg="#FF0000")
                            elif mode == "2":
                                self.cc_indicator.config(text="\u2B24 CC: DND", fg="#FFFF00")
                        except Exception:
                            pass
            except queue.Empty:
                break

        if latest_sts:
            self.update_display(latest_sts)

        self.after(20, self.process_serial_queue)

    def is_numeric_or_empty(self, s: str) -> bool:
        """Utility function to validate signal/register integers."""
        return s == "" or s.isdigit()

    def update_display(self, line: str):
        """Parse the Uniden serial payload and refresh LCD and activity logger states."""
        try:
            line = line.strip("\r\n\x00")
            if not line.startswith("STS,"):
                return
            line = line[4:]

            uid_raw = ""
            tgid_name = ""

            m_uid = re.search(r"UID\s*[:\s]\s*([A-Za-z0-9_\-\. ]+)", line, re.IGNORECASE)
            if m_uid:
                candidate_uid = m_uid.group(1).strip()
                if candidate_uid and not is_status_line(candidate_uid):
                    uid_raw = candidate_uid

            m_tgid = re.search(r"TGID\s*[:\s]\s*([A-Za-z0-9_\-\. ]+)", line, re.IGNORECASE)
            if m_tgid:
                raw_t = m_tgid.group(1).strip()
                nums = re.findall(r"\d+", raw_t)
                tgid_name = nums[-1] if nums else raw_t

            fields = [x.strip() for x in line.split(",")]

            hw_idx = -1
            for i in range(len(fields) - 5, max(-1, len(fields) - 16), -1):
                f_sq = fields[i].strip()
                f_mute = fields[i + 1].strip()
                f_vol = fields[i + 2].strip()
                f_sql = fields[i + 3].strip()
                f_sig = fields[i + 4].strip()

                if (
                    f_sq in ["0", "1"]
                    and f_mute in ["0", "1"]
                    and self.is_numeric_or_empty(f_vol)
                    and self.is_numeric_or_empty(f_sql)
                    and self.is_numeric_or_empty(f_sig)
                ):
                    hw_idx = i
                    break

            sig_val = 0
            if hw_idx != -1:
                sig_str = fields[hw_idx + 4].strip()
                if sig_str.isdigit():
                    sig_val = min(int(sig_str), 5)
                fields = fields[:hw_idx]

            sig_text = f"SIG: {'■ ' * sig_val}{'□ ' * (5 - sig_val)}"
            current_sig_color = ["#555555", "#00FF00", "#ADFF2F", "#FFFF00", "#FFA500", "#FF0000"][sig_val]

            raw_lines = []
            idx = 0

            while idx < len(fields):
                idx += 1
                txt = fields[idx] if idx < len(fields) else ""
                idx += 1

                while idx < len(fields):
                    next_fmt = fields[idx].strip()
                    is_valid_fmt = next_fmt in ("", "1") or bool(re.fullmatch(r"^[0-9Rr* ]+$", next_fmt))
                    if is_valid_fmt:
                        break
                    txt += "," + fields[idx]
                    idx += 1

                raw_lines.append(clean_uniden_lcd(txt))

            display_lines = []
            for i, txt in enumerate(raw_lines):
                display_txt = self.catchers[i].update(txt) if i < len(self.catchers) else txt
                display_txt = display_txt.replace(">", "▶")
                display_lines.append(display_txt.ljust(26, " ")[:26])

            for i in range(6):
                if i < len(display_lines):
                    self.lcd_canvas.itemconfig(self.lcd_texts[i], text="  " + display_lines[i])
                else:
                    self.lcd_canvas.itemconfig(self.lcd_texts[i], text="")

            for t_line in raw_lines:
                u_match = re.search(r"UID\s*[:\s]\s*([A-Za-z0-9_\-\. ]+)", t_line, re.IGNORECASE)
                if u_match:
                    cand = u_match.group(1).strip()
                    if cand and not is_status_line(cand):
                        uid_raw = cand
                t_match = re.search(r"TGID\s*[:\s]\s*([A-Za-z0-9_\-\. ]+)", t_line, re.IGNORECASE)
                if t_match:
                    t_cand = t_match.group(1).strip()
                    t_nums = re.findall(r"\d+", t_cand)
                    tgid_name = t_nums[-1] if t_nums else t_cand

            full_text_upper = "\n".join(display_lines).upper()

            if "CC DND" in full_text_upper:
                self.cc_indicator.config(text="\u2B24 CC: DND", fg="#FFFF00")
            elif "CC PRI" in full_text_upper:
                self.cc_indicator.config(text="\u2B24 CC: PRI", fg="#FF0000")
            elif "CC OFF" in full_text_upper:
                self.cc_indicator.config(text="\u2B24 CC: OFF", fg="#555555")

            is_menu = any(kw in full_text_upper for kw in ("MENU", "SETTINGS", "SELECTION"))

            if is_menu:
                self.status_label.config(text="--- MENU ---", fg="#00FFFF")
                self._last_scan_state = "MENU"
                if self.active_call:
                    self.commit_log()
            else:
                l3 = clean_text_for_log(raw_lines[2]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 2 else ""
                l4 = clean_text_for_log(raw_lines[3]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 3 else ""
                l5 = clean_text_for_log(raw_lines[4]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 4 else ""
                l6 = clean_text_for_log(raw_lines[5]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 5 else ""

                u5 = l5.upper()
                is_trunked_search = any(u5.startswith(p) for p in ("ID SEARCH", "ID SCAN", "LINK", "FIND", "UID:", "UID ", "TGID:", "TGID "))

                is_call_active = False
                call_sys, call_dept, call_chan = "", "", ""

                if is_trunked_search:
                    if l6 and not is_status_line(l6):
                        is_call_active = True
                        call_sys, call_dept, call_chan = l3, l4, l6
                else:
                    if l6 and not is_status_line(l6) and l5 and not is_status_line(l5):
                        is_call_active = True
                        call_sys, call_dept, call_chan = l3, l4, l5

                if is_call_active:
                    if not self.active_call:
                        self.active_call = True
                        self.current_call_start = time.time()
                        self.log_sys = ScrollCatcher()
                        self.log_dept = ScrollCatcher()
                        self.log_chan = ScrollCatcher()

                    self.log_sys.update(call_sys)
                    self.log_dept.update(call_dept)
                    self.log_chan.update(call_chan)

                    if uid_raw:
                        self.current_uid = uid_raw
                    if tgid_name:
                        self.current_tgid = tgid_name

                    if self._last_scan_state != "=== ACTIVE ===":
                        self.status_label.config(text="=== ACTIVE ===", fg="#FF0000")
                        self._last_scan_state = "=== ACTIVE ==="
                else:
                    if self.active_call:
                        self.commit_log()

                    if self._last_scan_state != "- SCANNING -":
                        self.status_label.config(text="- SCANNING -", fg="#39FF14")
                        self._last_scan_state = "- SCANNING -"

            if sig_text != self._last_sig or current_sig_color != self._last_sig_color:
                self.sig_label.config(text=sig_text, fg=current_sig_color)
                self._last_sig, self._last_sig_color = sig_text, current_sig_color

        except Exception:
            pass


if __name__ == "__main__":
    app = VirtualScanner()
    app.mainloop()
