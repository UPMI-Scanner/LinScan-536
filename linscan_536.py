#!/usr/bin/env python3
import tkinter as tk
from tkinter import simpledialog, filedialog, ttk
import serial
import re
import glob
import datetime
import os
import subprocess
import socket
import time
import threading
import csv

BAUD = 115200
CLEAN_REGEX = re.compile(r'[^\x20-\x7E]')

def clean_text(text):
    return CLEAN_REGEX.sub('', text).strip()
    
def keep_spaces(text):
    return CLEAN_REGEX.sub('', text)

class ScrollCatcher:
    def __init__(self):
        self.full_text = ""
        self.last_seen = ""

    def update(self, current):
        if not current.strip():
            self.full_text = self.last_seen = current
            return current

        if not self.full_text:
            self.full_text = self.last_seen = current
            return self.full_text

        if current == self.last_seen:
            return self.full_text

        prefix_len = 0
        for i in range(min(len(self.last_seen), len(current))):
            if self.last_seen[i] == current[i]: prefix_len += 1
            else: break
        
        last_rem, curr_rem = self.last_seen[prefix_len:], current[prefix_len:]
        
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

class ProScanRTSPEngine(threading.Thread):
    def __init__(self, scanner_ip, mp3_file, log_callback):
        super().__init__()
        self.ip = scanner_ip
        self.mp3_file = mp3_file
        self.log_callback = log_callback
        self.running = True
        self.tcp_sock = self.udp_sock = self.ffmpeg_proc = None
        self.start_time = datetime.datetime.now()

    def run(self):
        audio_filter = "volume=3.0,silenceremove=start_periods=1:start_duration=0.05:start_threshold=-38dB:stop_periods=-1:stop_duration=0.8:stop_threshold=-38dB"
        ffmpeg_cmd = [
            'ffmpeg', '-nostdin', '-hide_banner', '-loglevel', 'warning', '-y',
            '-f', 'mulaw', '-ar', '8000', '-ac', '1', '-i', 'pipe:0',
            '-af', audio_filter, '-c:a', 'libmp3lame', '-b:a', '64k', self.mp3_file
        ]
        try:
            self.ffmpeg_proc = subprocess.Popen(ffmpeg_cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.log_callback(f"[REC ERROR] FFmpeg start failed: {str(e)}")
            return

        while self.running:
            try:
                self.connect_and_stream()
            except Exception as e:
                if self.running:
                    self.log_callback(f"[REC WARN] Stream drop ({str(e)}). Reconnecting...")
                    self.close_sockets()
                    time.sleep(2)

        self.cleanup()

    def connect_and_stream(self):
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp_sock.bind(('0.0.0.0', 0))
        rtp_port, rtcp_port = self.udp_sock.getsockname()[1], self.udp_sock.getsockname()[1] + 1
        self.udp_sock.settimeout(2.0)

        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.settimeout(5.0)
        self.tcp_sock.connect((self.ip, 554))

        cseq = 1
        reqs = [
            f"OPTIONS rtsp://{self.ip}/au:scanner.au RTSP/1.0\r\nCSeq: {{}}\r\nUser-Agent: LinScan-536\r\n\r\n",
            f"DESCRIBE rtsp://{self.ip}/au:scanner.au RTSP/1.0\r\nCSeq: {{}}\r\nUser-Agent: LinScan-536\r\nAccept: application/sdp\r\n\r\n",
            f"SETUP rtsp://{self.ip}/au:scanner.au/trackID=1 RTSP/1.0\r\nCSeq: {{}}\r\nUser-Agent: LinScan-536\r\nTransport: RTP/AVP;unicast;client_port={rtp_port}-{rtcp_port}\r\n\r\n"
        ]

        for req in reqs[:2]:
            self.tcp_sock.sendall(req.format(cseq).encode())
            self.tcp_sock.recv(1024)
            cseq += 1

        self.tcp_sock.sendall(reqs[2].format(cseq).encode())
        resp = self.tcp_sock.recv(1024).decode(errors='ignore')
        cseq += 1

        session_id = (re.search(r'Session:\s*([^\r\n;]+)', resp, re.IGNORECASE) or [None, ""])[1].strip()
        server_port = int((re.search(r'server_port=\s*([0-9]+)', resp, re.IGNORECASE) or [None, 5004])[1])

        req = f"PLAY rtsp://{self.ip}/au:scanner.au/ RTSP/1.0\r\nCSeq: {cseq}\r\nUser-Agent: LinScan-536\r\nSession: {session_id}\r\nRange: npt=0.000-\r\n\r\n"
        self.tcp_sock.sendall(req.encode())
        self.tcp_sock.recv(1024)
        cseq += 1

        try:
            for p in [server_port, 5000, 5004, 5006]: self.udp_sock.sendto(b'\x80\x00\x00\x00', (self.ip, p))
        except Exception: pass

        last_ping = time.time()
        while self.running:
            if time.time() - last_ping > 10.0:
                try:
                    self.tcp_sock.sendall(f"OPTIONS rtsp://{self.ip}/au:scanner.au RTSP/1.0\r\nCSeq: {cseq}\r\nSession: {session_id}\r\nUser-Agent: LinScan-536\r\n\r\n".encode())
                    self.tcp_sock.recv(512)
                    cseq += 1
                except Exception: pass
                last_ping = time.time()

            try:
                data, _ = self.udp_sock.recvfrom(2048)
                if len(data) > 12 and self.ffmpeg_proc and self.ffmpeg_proc.stdin:
                    try:
                        self.ffmpeg_proc.stdin.write(data[12:])
                        self.ffmpeg_proc.stdin.flush()
                    except (BrokenPipeError, OSError): break
            except socket.timeout: continue

    def stop(self):
        self.running = False
        if self.tcp_sock:
            try: self.tcp_sock.sendall(f"TEARDOWN rtsp://{self.ip}/au:scanner.au/ RTSP/1.0\r\nCSeq: 99\r\nUser-Agent: LinScan-536\r\n\r\n".encode())
            except Exception: pass
        self.close_sockets()

    def close_sockets(self):
        for sock in (self.tcp_sock, self.udp_sock):
            if sock:
                try: sock.close()
                except Exception: pass
        self.tcp_sock = self.udp_sock = None

    def cleanup(self):
        self.close_sockets()
        if self.ffmpeg_proc:
            try:
                if self.ffmpeg_proc.stdin: self.ffmpeg_proc.stdin.close()
                self.ffmpeg_proc.wait(timeout=3)
            except Exception:
                try: self.ffmpeg_proc.kill()
                except Exception: pass
            self.ffmpeg_proc = None

        if os.path.exists(self.mp3_file):
            try:
                if os.path.getsize(self.mp3_file) < 20000:
                    os.remove(self.mp3_file)
                    self.log_callback("[SYSTEM] Auto-purged short noise spike (< 2 sec).")
                else:
                    new_name = f"Session_{self.start_time.strftime('%Y-%m-%d_%I-%M-%S%p')}_to_{datetime.datetime.now().strftime('%I-%M-%S%p')}.mp3"
                    new_path = os.path.join(os.path.dirname(self.mp3_file), new_name)
                    if os.path.exists(new_path): os.remove(new_path)
                    os.rename(self.mp3_file, new_path)
                    self.log_callback(f"[SYSTEM] Audio Saved: {new_name}")
            except Exception: pass


class VirtualScanner(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("LinScan-536")
        self.geometry("1100x780")
        self.minsize(1050, 650) 
        self.configure(bg="#050505")
        
        self.ser = self.rtsp_engine = None
        self.serial_buffer = b""
        self.catchers = [ScrollCatcher() for _ in range(20)]
        self.active_call = self.record_enabled = self._ignore_slider_events = False
        self.current_uid = self.current_tgid = self.scanner_ip = ""
        self.log_sys = ScrollCatcher()
        self.log_dept = ScrollCatcher()
        self.log_chan = ScrollCatcher()
        self.tg_hits = {}

        self.ip_file = os.path.expanduser("~/linscan_ip.txt")
        self.load_ip()
        
        self._last_sts_line = self._last_status = self._last_sig = self._last_sig_color = ""
        self._last_screen = "Initializing LCD..."
        self._last_scan_state = None

        self.faceplate = tk.Frame(self, bg="#1a1a1a", bd=4, relief=tk.RAISED)
        self.faceplate.pack(fill=tk.X, padx=15, pady=15)
        self.software_panel = tk.Frame(self, bg="#050505")
        self.software_panel.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        # --- VOL & SQL PANEL ---
        self.vol_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.vol_panel.pack(side=tk.LEFT, fill=tk.Y, padx=20, pady=20)
        
        for name, to_val, cmd_func in [("VOL", 29, self.send_volume), ("SQL", 19, self.send_squelch)]:
            sub = tk.Frame(self.vol_panel, bg="#1a1a1a")
            sub.pack(side=tk.LEFT, padx=5)
            tk.Label(sub, text=name, fg="#888888", bg="#1a1a1a", font=("Arial", 11, "bold")).pack(pady=(0,5))
            slider = tk.Scale(sub, from_=to_val, to=0, orient=tk.VERTICAL, bg="#111111", fg="#39FF14" if name=="VOL" else "#00FFFF", 
                              troughcolor="#050505", bd=1, highlightthickness=0, relief=tk.SUNKEN, activebackground="#2a2a2a", command=cmd_func, length=180)
            slider.pack(fill=tk.Y, expand=True)
            if name == "VOL": self.vol_slider = slider
            else: self.sql_slider = slider

        # --- KEYPAD PANEL ---
        self.keypad_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.keypad_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=20, pady=20)
        self.center_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.center_panel.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.knob = tk.Canvas(self.keypad_panel, width=100, height=100, bg="#1a1a1a", highlightthickness=0)
        self.knob.pack(pady=(0, 15))
        self.knob.create_oval(5, 5, 95, 95, fill="#222222", outline="#111111")
        self.knob.create_oval(10, 10, 90, 90, fill="#777777", outline="#555555")
        self.knob.create_oval(20, 20, 80, 80, fill="#AAAAAA", outline="")
        self.knob.create_oval(30, 30, 70, 70, fill="#DDDDDD", outline="#888888")
        self.knob.create_text(25, 50, text="◀", fill="#111111", font=("Arial", 14))
        self.knob.create_text(75, 50, text="▶", fill="#111111", font=("Arial", 14))
        self.knob.create_text(50, 50, text="FUNC", fill="#111111", font=("Arial", 9, "bold"))
        self.knob.bind("<Button-1>", lambda e: self.send_key('<') if e.x < 35 else (self.send_key('>') if e.x > 65 else self.send_key('F')))

        btn_style = {"font": ("Arial", 10, "bold"), "bg": "#111111", "fg": "#FFFFFF", "bd": 1, "activebackground": "#333333", "activeforeground": "#FFFFFF", "cursor": "hand2"}
        for row in [[("RANGE", 'R'), ("CLOSE CALL", 'Q')], [("MENU", 'M'), ("REPLAY", 'Y')], [("1", '1'), ("2", '2'), ("3", '3')], [("4", '4'), ("5", '5'), ("6", '6')], [("7", '7'), ("8", '8'), ("9", '9')], [(". / NO", '.'), ("0", '0'), ("E / YES", 'E')]]:
            row_f = tk.Frame(self.keypad_panel, bg="#1a1a1a")
            row_f.pack(fill=tk.X, pady=3)
            for text, key_code in row:
                tk.Button(row_f, text=text, width=12 if len(row) == 2 else 7, height=1, command=lambda k=key_code: self.send_key(k), **btn_style).pack(side=tk.LEFT, padx=3, expand=True)

        self.lcd_header = tk.Frame(self.center_panel, bg="#1a1a1a")
        self.lcd_header.pack(fill=tk.X, padx=20, pady=(0, 5))
        
        tk.Label(self.lcd_header, text="UNIDEN BCD536HP", fg="#AAAAAA", bg="#1a1a1a", font=("Arial", 14, "bold")).pack(side=tk.LEFT)
        self.status_label = tk.Label(self.lcd_header, text="CONNECTING...", fg="#39FF14", bg="#1a1a1a", font=("Courier", 14, "bold"))
        self.status_label.pack(side=tk.RIGHT)
        self.sig_label = tk.Label(self.lcd_header, text="SIG: \u25a1 \u25a1 \u25a1 \u25a1 \u25a1", fg="#555555", bg="#1a1a1a", font=("Courier", 14, "bold"))
        self.sig_label.pack(side=tk.RIGHT, padx=15)
        self.cc_indicator = tk.Label(self.lcd_header, text="\u2B24 CC: SYNC", fg="#555555", bg="#1a1a1a", font=("Arial", 14, "bold"))
        self.cc_indicator.pack(side=tk.RIGHT, padx=15)

        self.bezel = tk.Frame(self.center_panel, bg="#050505", highlightthickness=2, highlightbackground="#333333")
        self.bezel.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)
        self.lcd_canvas = tk.Canvas(self.bezel, bg="#050505", highlightthickness=0)
        self.lcd_canvas.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        self.lcd_text = None
        self.lcd_canvas.bind("<Configure>", self.draw_lcd)
        self.lcd_font = ("Courier", 18, "bold")

        soft_f = tk.Frame(self.center_panel, bg="#1a1a1a")
        soft_f.pack(fill=tk.X, padx=20, pady=(10, 5))
        for text, key_code in [("SYS", 'A'), ("DEPT", 'B'), ("CH", 'C'), ("AVOID", 'L'), ("ZIP", 'Z'), ("SERV", 'S')]:
            tk.Button(soft_f, text=text, height=2, command=lambda k=key_code: self.send_key(k), **btn_style).pack(side=tk.LEFT, padx=4, expand=True, fill=tk.X)

        # --- ACTIVITY LOG CONTROL BAR ---
        self.log_ctrl_frame = tk.Frame(self.software_panel, bg="#050505")
        self.log_ctrl_frame.pack(fill=tk.X, pady=(0, 5))
        tk.Label(self.log_ctrl_frame, text="ACTIVITY TABLE (Double-click row to Hold Channel)", fg="#00FFFF", bg="#050505", font=("Courier", 11, "bold")).pack(side=tk.LEFT)
        
        btn_config = {"font": ("Arial", 9, "bold"), "bg": "#1a1a1a", "bd": 0, "cursor": "hand2"}
        for txt, fg_col, cmd in [("CLEAR LOG", "#00FFFF", self.clear_log), ("EXPORT CSV", "#39FF14", self.export_csv), ("FOLDER", "#00FFFF", self.open_audio_folder)]:
            tk.Button(self.log_ctrl_frame, text=txt, fg=fg_col, command=cmd, **btn_config).pack(side=tk.RIGHT, padx=4)
            
        self.ip_btn = tk.Button(self.log_ctrl_frame, text="SET IP", fg="#FFFF00", command=self.set_ip, **btn_config)
        self.ip_btn.pack(side=tk.RIGHT, padx=4)
        self.wifi_rec_btn = tk.Button(self.log_ctrl_frame, text="○ WIFI REC", fg="#888888", command=self.toggle_wifi_record, **btn_config)
        self.wifi_rec_btn.pack(side=tk.RIGHT, padx=4)
        self.sd_rec_btn = tk.Button(self.log_ctrl_frame, text="SD REC", fg="#FF0000", command=self.toggle_sd_record, **btn_config)
        self.sd_rec_btn.pack(side=tk.RIGHT, padx=4)

        # --- DEDUPLICATED TALKGROUP TABLE ---
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#FFFFFF", foreground="#000000", fieldbackground="#FFFFFF", rowheight=32, font=("Arial", 12, "bold"))
        style.configure("Treeview.Heading", background="#D0D0D0", foreground="#000000", font=("Arial", 11, "bold"), relief="raised")
        style.map("Treeview", background=[("selected", "#0055FF")], foreground=[("selected", "#FFFFFF")])

        self.tree_columns = ("time", "sys", "dept", "chan", "tgid", "uid", "hits")
        self.log_tree = ttk.Treeview(self.software_panel, columns=self.tree_columns, show="headings", selectmode="browse")
        
        cols_config = [("time", "LAST SEEN", 125, "center"), ("sys", "SYSTEM", 190, "w"), ("dept", "DEPARTMENT", 190, "w"), ("chan", "CHANNEL", 190, "w"), 
                       ("tgid", "TGID", 85, "center"), ("uid", "LAST UID", 110, "center"), ("hits", "HITS", 65, "center")]
        for col_id, heading, width, anchor in cols_config:
            self.log_tree.heading(col_id, text=heading)
            self.log_tree.column(col_id, width=width, anchor=anchor)

        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.scrollbar = tk.Scrollbar(self.software_panel, command=self.log_tree.yview, bg="#1a1a1a", troughcolor="#050505", bd=0)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_tree.config(yscrollcommand=self.scrollbar.set)

        self.log_tree.bind("<Double-1>", lambda e: self.send_key('H') if self.log_tree.selection() else None)
        self.bind_all("<Key>", self.handle_keypress)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.poll_connection()
        self.request_data()
        self.read_data()

    def handle_keypress(self, event):
        sym, key = event.keysym, event.char.lower()
        if sym == "Escape": self.send_key('L')
        elif sym in ("Return", "KP_Enter"): self.send_key('E')
        elif sym == "space": self.send_key('H')
        elif key in "0123456789abcmy.": self.send_key(key.upper())

    def open_audio_folder(self):
        audio_dir = os.path.expanduser("~/LinScan_Audio")
        os.makedirs(audio_dir, exist_ok=True)
        subprocess.Popen(["xdg-open", audio_dir])

    def export_csv(self):
        items = self.log_tree.get_children()
        if not items: return
        default_name = f"LinScan_Log_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        out_path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile=default_name, filetypes=[("CSV Files", "*.csv")])
        if out_path:
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Last Seen", "System", "Department", "Channel", "TGID", "Last UID", "Hits"])
                for item in items: writer.writerow(self.log_tree.item(item)["values"])

    def load_ip(self):
        try:
            if os.path.exists(self.ip_file):
                with open(self.ip_file, "r") as f: self.scanner_ip = f.read().strip()
        except Exception: pass

    def set_ip(self):
        new_ip = simpledialog.askstring("Scanner IP", "Enter Uniden Wi-Fi IP Address:\n(e.g., 192.168.1.15)", initialvalue=self.scanner_ip, parent=self)
        if new_ip and new_ip.strip():
            self.scanner_ip = new_ip.strip()
            try:
                with open(self.ip_file, "w") as f: f.write(self.scanner_ip)
            except Exception: pass

    def toggle_sd_record(self):
        if self.ser and self.ser.is_open:
            try:
                self.ser.write(b'KEY,F,P\r')
                self.after(300, lambda: self.ser.write(b'KEY,Y,P\r'))
            except Exception: pass

    def toggle_wifi_record(self):
        if not self.scanner_ip:
            self.set_ip()
            if not self.scanner_ip: return

        self.record_enabled = not self.record_enabled
        if self.record_enabled:
            self.wifi_rec_btn.config(text="● WIFI REC", fg="#FF0000")
            os.makedirs(os.path.expanduser("~/LinScan_Audio"), exist_ok=True)
            vox_file = os.path.expanduser(f"~/LinScan_Audio/Session_VOX_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.mp3")
            self.rtsp_engine = ProScanRTSPEngine(self.scanner_ip, vox_file, lambda msg: None)
            self.rtsp_engine.daemon = True
            self.rtsp_engine.start()
        else:
            self.wifi_rec_btn.config(text="○ WIFI REC", fg="#888888")
            if self.rtsp_engine:
                self.rtsp_engine.stop()
                self.rtsp_engine.join(timeout=4.0)
                self.rtsp_engine = None

    def draw_lcd(self, event=None):
        width, height = self.lcd_canvas.winfo_width(), self.lcd_canvas.winfo_height()
        if width < 50 or height < 50: return
        self.lcd_canvas.delete("bg_shape")
        r, c = 20, "#FFA500" 
        for coords in [(0, 0, 2*r, 2*r), (width-2*r, 0, width, 2*r), (0, height-2*r, 2*r, height), (width-2*r, height-2*r, width, height)]:
            self.lcd_canvas.create_oval(*coords, fill=c, outline=c, tags="bg_shape")
        self.lcd_canvas.create_rectangle(r, 0, width-r, height, fill=c, outline=c, tags="bg_shape")
        self.lcd_canvas.create_rectangle(0, r, width, height-r, fill=c, outline=c, tags="bg_shape")
        
        if self.lcd_text is None: self.lcd_text = self.lcd_canvas.create_text(20, 20, text=self._last_screen, fill="#000000", font=self.lcd_font, anchor="nw", justify="left")
        else: self.lcd_canvas.tag_raise(self.lcd_text)

    def on_closing(self):
        self.record_enabled = False
        if self.rtsp_engine:
            self.rtsp_engine.stop()
            self.rtsp_engine.join(timeout=3.0)
        if self.ser and self.ser.is_open: self.ser.close()
        self.destroy()

    def clear_log(self):
        for item in self.log_tree.get_children(): self.log_tree.delete(item)
        self.tg_hits.clear()

    def send_key(self, key_code):
        if self.ser and self.ser.is_open:
            try: self.ser.write(f"KEY,{key_code},P\r".encode('ascii'))
            except Exception: pass
                
    def send_volume(self, val):
        if getattr(self, '_ignore_slider_events', False): return
        if self.ser and self.ser.is_open:
            try: self.ser.write(f"VOL,{int(val):02d}\r".encode('ascii'))
            except Exception: pass
            
    def send_squelch(self, val):
        if getattr(self, '_ignore_slider_events', False): return
        if self.ser and self.ser.is_open:
            try: self.ser.write(f"SQL,{int(val):02d}\r".encode('ascii'))
            except Exception: pass

    def poll_connection(self):
        if not self.ser or not self.ser.is_open:
            ports = sorted(glob.glob('/dev/ttyACM*') + glob.glob('/dev/ttyUSB*'))
            if not ports:
                if self._last_status != "NO USB DETECTED":
                    self.status_label.config(text="NO USB DETECTED", fg="#FF0033")
                    self._last_status = "NO USB DETECTED"
            else:
                for p in ports:
                    try:
                        self.ser = serial.Serial(p, BAUD, timeout=0)
                        self.serial_buffer = b""
                        self.status_label.config(text=f"CONNECTED ({os.path.basename(p)})", fg="#39FF14")
                        self._last_status = "CONNECTED"
                        self.ser.write(b'VOL\rSQL\r')
                        break
                    except PermissionError:
                        self.status_label.config(text="PERM DENIED", fg="#FF0033")
                        self._last_status = "PERM DENIED"
                    except Exception:
                        self.status_label.config(text="PORT ERROR", fg="#FF0033")
                        self._last_status = "PORT ERROR"
        self.after(2000, self.poll_connection)

    def request_data(self):
        if self.ser and self.ser.is_open:
            try: self.ser.write(b'STS\r')
            except Exception: self.ser.close()
        self.after(150, self.request_data)

    def read_data(self):
        if self.ser and self.ser.is_open:
            try:
                if self.ser.in_waiting: self.serial_buffer += self.ser.read(self.ser.in_waiting)
                while b'\r' in self.serial_buffer:
                    raw_line, self.serial_buffer = self.serial_buffer.split(b'\r', 1)
                    line = raw_line.decode('ascii', errors='ignore').strip()
                    if line.startswith('STS,') and line != self._last_sts_line:
                        self.update_display(line)
                        self._last_sts_line = line
                    elif line.startswith('VOL,'):
                        try:
                            self._ignore_slider_events = True
                            self.vol_slider.set(int(line.split(',')[1]))
                            self._ignore_slider_events = False
                        except Exception: pass
                    elif line.startswith('SQL,'):
                        try:
                            self._ignore_slider_events = True
                            self.sql_slider.set(int(line.split(',')[1]))
                            self._ignore_slider_events = False
                        except Exception: pass
            except Exception: self.ser.close()
        self.after(20, self.read_data)

    def update_display(self, line):
        fields = line.split(',')
        if len(fields) < 11: return

        sig_val = next((int(fields[offset]) for offset in [-3, -4, -5] if len(fields) >= abs(offset) and fields[offset].isdigit() and 0 <= int(fields[offset]) <= 5), 0)
        sig_text = f"SIG: {'\u25a0 ' * sig_val}{'\u25a1 ' * (5 - sig_val)}"
        current_sig_color = ["#555555", "#00FF00", "#ADFF2F", "#FFFF00", "#FFA500", "#FF0000"][sig_val]

        uid_raw = tgid_name = ""
        for field in fields[11:]:
            text = clean_text(field).upper()
            if "UID:" in text: uid_raw = text.replace("UID:", "").strip()
            elif "TGID:" in text: tgid_name = text.replace("TGID:", "").strip()

        screen_lines = []
        for i, fld_idx in enumerate(range(2, min(len(fields) - 8, 42), 2)):
            clean_line = keep_spaces(fields[fld_idx])
            screen_lines.append(self.catchers[i].update(clean_line))
            upper_line = clean_line.upper()
            if "CC DND" in upper_line: self.cc_indicator.config(text="\u2B24 CC: DND", fg="#FFFF00")
            elif "CC PRI" in upper_line: self.cc_indicator.config(text="\u2B24 CC: PRI", fg="#FF0000")
            elif "CC OFF" in upper_line: self.cc_indicator.config(text="\u2B24 CC: OFF", fg="#555555")

        while screen_lines and not screen_lines[-1].strip(): screen_lines.pop()
        screen_text = "\n".join(l.rstrip() for l in screen_lines)
        is_scanning = any(x in screen_text.upper() for x in ("SCAN", "ID SEARCH", "SEARCHING"))

        if is_scanning:
            if self.active_call:
                sys_final, dept_final, chan_final = self.log_sys.full_text.strip(), self.log_dept.full_text.strip(), self.log_chan.full_text.strip()
                chan_upper = chan_final.upper()
                
                if chan_final and not any(x in chan_upper for x in ("SCAN", "ID SEARCH", "SEARCHING")):
                    tg_key = self.current_tgid or chan_final
                    self.tg_hits[tg_key] = self.tg_hits.get(tg_key, 0) + 1
                    row_vals = (datetime.datetime.now().strftime("%I:%M:%S %p"), sys_final, dept_final, chan_final, self.current_tgid, self.current_uid, self.tg_hits[tg_key])
                    
                    if self.log_tree.exists(tg_key):
                        self.log_tree.item(tg_key, values=row_vals)
                        self.log_tree.move(tg_key, "", 0)
                    else:
                        self.log_tree.insert("", 0, iid=tg_key, values=row_vals)

                self.active_call = False
                self.current_uid = self.current_tgid = ""
                self.log_sys, self.log_dept, self.log_chan = ScrollCatcher(), ScrollCatcher(), ScrollCatcher()
        else:
            if not self.active_call:
                self.active_call = True
                self.current_uid = self.current_tgid = ""
                self.log_sys, self.log_dept, self.log_chan = ScrollCatcher(), ScrollCatcher(), ScrollCatcher()
                
            if len(fields) > 10:
                self.log_sys.update(clean_text(fields[6]))
                self.log_dept.update(clean_text(fields[8]))
                self.log_chan.update(clean_text(fields[10]))
            
            if uid_raw: self.current_uid = uid_raw
            if tgid_name: self.current_tgid = tgid_name

        if is_scanning != self._last_scan_state:
            self.status_label.config(text="- SCANNING -" if is_scanning else "=== ACTIVE ===", fg="#39FF14" if is_scanning else "#FF0000")
            self._last_scan_state = is_scanning

        if sig_text != self._last_sig or current_sig_color != self._last_sig_color:
            self.sig_label.config(text=sig_text, fg=current_sig_color)
            self._last_sig, self._last_sig_color = sig_text, current_sig_color

        if screen_text != self._last_screen:
            self._last_screen = screen_text
            if self.lcd_text is not None: self.lcd_canvas.itemconfig(self.lcd_text, text=screen_text)

if __name__ == "__main__":
    app = VirtualScanner()
    app.mainloop()
