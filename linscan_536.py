#!/usr/bin/env python3
"""
LinScan-536 Pro: Computer-Aided Scanning (CAS) suite,
activity logger, per-call audio recorder, UID alias manager, and web dashboard
for Uniden BCD536HP / SDS200 digital scanners over USB Serial and Wi-Fi UDP/RTSP.

Repository: https://github.com/UPMI-Scanner/LinScan-536
License: MIT
"""

from __future__ import annotations

from collections import deque
import csv
from dataclasses import dataclass
import datetime
import glob
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import linscan_pro
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import queue
import re
import shutil
import socket
import subprocess
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any
import xml.etree.ElementTree as ET

import serial
from serial.tools import list_ports

BAUD_RATE = 115200
UDP_SCANNER_PORT = 50536
DEFAULT_RTP_CLIENT_PORT = 50538  # Even/odd pair 50538-50539 (friendly for UFW rules)
RTSP_KEEPALIVE_DEFAULT_SEC = 15.0
RTSP_STALL_TIMEOUT_SEC = 10.0
UDP_NO_REPLY_TIMEOUT_SEC = 8.0
PRE_ROLL_MAX_BYTES = 4000  # ~0.5 sec of 8kHz 8-bit mu-law audio
MAX_LOG_ROWS = 1000
MAX_HISTORY_ROWS = 2500

UID_REGEX = re.compile(r"UID\s*[:\s]\s*([A-Za-z0-9_\-\. ]+)", re.IGNORECASE)
TGID_REGEX = re.compile(r"TGID\s*[:\s]\s*([A-Za-z0-9_\-\. ]+)", re.IGNORECASE)
FREQ_REGEX = re.compile(r"\b(\d{2,3}\.\d{3,5})\s*(?:MHz)?\b", re.IGNORECASE)
NUM_REGEX = re.compile(r"\d+")
FMT_REGEX = re.compile(r"^[0-9Rr* ]+$")
SESSION_REGEX = re.compile(r"Session:\s*([^\r\n;]+)", re.IGNORECASE)
SESSION_TIMEOUT_REGEX = re.compile(r"Session:[^\r\n]*timeout\s*=\s*(\d+)", re.IGNORECASE)
SERVER_PORT_REGEX = re.compile(r"server_port=\s*([0-9]+)", re.IGNORECASE)
CONTENT_LENGTH_REGEX = re.compile(r"Content-Length:\s*(\d+)", re.IGNORECASE)
SDP_CONTROL_REGEX = re.compile(r"^a=control:(.+)$", re.IGNORECASE | re.MULTILINE)
SAFE_FILENAME_REGEX = re.compile(r"[^A-Za-z0-9_\-]+")

CONFIG_DIR = Path.home() / ".config" / "linscan"
CONFIG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = CONFIG_DIR / "linscan.log"

log_handler = RotatingFileHandler(
    LOG_FILE, maxBytes=1_000_000, backupCount=2, encoding="utf-8"
)
logging.basicConfig(
    handlers=[log_handler],
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)


@dataclass
class GSITelemetry:
    """Structured telemetry parsed from the Uniden GSI XML response."""

    mode: str = ""
    system: str = ""
    department: str = ""
    channel: str = ""
    frequency: str = ""
    modulation: str = ""
    tgid: str = ""
    uid: str = ""
    site: str = ""
    rssi: int = 0
    squelch_open: bool = False
    mute: bool = False


def parse_gsi_xml(raw_line: str) -> GSITelemetry | None:
    """Parse Uniden GSI,<XML> response into structured GSITelemetry."""
    xml_start = raw_line.find("<ScannerInfo")
    if xml_start == -1:
        return None
    xml_payload = raw_line[xml_start:].strip()
    try:
        root = ET.fromstring(xml_payload)
    except ET.ParseError as err:
        logging.debug("Failed to parse GSI XML payload: %s", err)
        return None

    telemetry = GSITelemetry(mode=root.attrib.get("Mode", ""))

    sys_el = root.find("System")
    if sys_el is not None:
        telemetry.system = sys_el.attrib.get("Name", "").strip()

    dept_el = root.find("Department")
    if dept_el is not None:
        telemetry.department = dept_el.attrib.get("Name", "").strip()

    site_el = root.find("Site")
    if site_el is not None:
        telemetry.site = site_el.attrib.get("Name", "").strip()

    tgid_el = root.find("TGID")
    if tgid_el is not None:
        telemetry.channel = tgid_el.attrib.get("Name", "").strip()
        raw_tgid = tgid_el.attrib.get("TGID", "").strip()
        nums = NUM_REGEX.findall(raw_tgid)
        telemetry.tgid = nums[-1] if nums else raw_tgid
        telemetry.modulation = tgid_el.attrib.get("Mod", "").strip()

    conv_el = root.find("ConvFrequency")
    if conv_el is not None:
        if not telemetry.channel:
            telemetry.channel = conv_el.attrib.get("Name", "").strip()
        telemetry.frequency = conv_el.attrib.get("Freq", "").strip()
        if not telemetry.modulation:
            telemetry.modulation = conv_el.attrib.get("Mod", "").strip()

    site_freq_el = root.find("SiteFrequency")
    if site_freq_el is not None and not telemetry.frequency:
        telemetry.frequency = site_freq_el.attrib.get("Freq", "").strip()

    uid_el = root.find("UnitID")
    if uid_el is not None:
        raw_uid = uid_el.attrib.get("U_Id", "").strip()
        if raw_uid.upper().startswith("UID:"):
            raw_uid = raw_uid[4:].strip()
        telemetry.uid = raw_uid

    prop_el = root.find("Property")
    if prop_el is not None:
        sig_str = prop_el.attrib.get("Sig", "0").strip()
        if sig_str.isdigit():
            telemetry.rssi = min(int(sig_str), 5)
        telemetry.mute = prop_el.attrib.get("Mute", "").upper() == "MUTE"
        sql_val = prop_el.attrib.get("P25Status", "")
        telemetry.squelch_open = not telemetry.mute and (
            telemetry.rssi > 0 or sql_val not in ("", "None")
        )

    return telemetry


def validate_scanner_ip(ip_str: str) -> str | None:
    """Return normalized IPv4 string if valid, otherwise None."""
    cleaned = ip_str.strip()
    if not cleaned:
        return None
    try:
        addr = ipaddress.IPv4Address(cleaned)
        return str(addr)
    except ValueError:
        return None


def read_rtsp_response(sock: socket.socket, timeout: float = 5.0) -> tuple[int, str, str]:
    """
    Read a complete RTSP response (status line, headers, and Content-Length body).
    Returns (status_code, headers_text, body_text).
    """
    sock.settimeout(timeout)
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise OSError("RTSP connection closed by scanner")
        buf += chunk
        if len(buf) > 65536:
            raise OSError("RTSP header exceeded 64KB limit")

    header_bytes, rest = buf.split(b"\r\n\r\n", 1)
    headers_text = header_bytes.decode("latin-1", errors="ignore")

    content_len = 0
    cl_match = CONTENT_LENGTH_REGEX.search(headers_text)
    if cl_match:
        content_len = int(cl_match.group(1))

    while len(rest) < content_len:
        chunk = sock.recv(min(4096, content_len - len(rest)))
        if not chunk:
            break
        rest += chunk

    body_text = rest[:content_len].decode("latin-1", errors="ignore") if content_len else ""
    first_line = headers_text.splitlines()[0] if headers_text else ""
    parts = first_line.split()
    status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    return status_code, headers_text, body_text


def bind_rtp_rtcp_pair(preferred_rtp_port: int = DEFAULT_RTP_CLIENT_PORT) -> tuple[socket.socket, socket.socket, int, int]:
    """
    Bind an even/odd UDP socket pair for RTP and RTCP per RFC 3550.
    Prefers predictable ports (e.g. 50538-50539) for clean UFW firewall rules,
    falling back to an OS-assigned even pair if busy.
    """
    candidates = [preferred_rtp_port, preferred_rtp_port + 2, preferred_rtp_port + 4]
    for port in candidates:
        if port % 2 != 0:
            port += 1
        rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtcp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            rtp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rtcp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            rtp_sock.bind(("0.0.0.0", port))
            rtcp_sock.bind(("0.0.0.0", port + 1))
            return rtp_sock, rtcp_sock, port, port + 1
        except OSError:
            rtp_sock.close()
            rtcp_sock.close()

    # Fallback: scan ephemeral range for an available even/odd pair
    for _ in range(32):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.bind(("0.0.0.0", 0))
        base = probe.getsockname()[1]
        probe.close()
        even_port = base if base % 2 == 0 else base + 1
        if even_port >= 65534:
            continue
        rtp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rtcp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            rtp_sock.bind(("0.0.0.0", even_port))
            rtcp_sock.bind(("0.0.0.0", even_port + 1))
            return rtp_sock, rtcp_sock, even_port, even_port + 1
        except OSError:
            rtp_sock.close()
            rtcp_sock.close()

    raise OSError("Unable to bind an even/odd UDP port pair for RTP/RTCP")


def test_wifi_scanner(
    scanner_ip: str,
    udp_port: int = UDP_SCANNER_PORT,
    rtsp_port: int = 554,
    timeout: float = 2.0,
) -> dict[str, Any]:
    """
    Probe both BCD536HP Wi-Fi endpoints (UDP 50536 control + TCP 554 RTSP audio)
    so users get instant ProScan-style diagnostic feedback.
    """
    result: dict[str, Any] = {
        "udp_ok": False,
        "udp_msg": "Not tested",
        "rtsp_ok": False,
        "rtsp_msg": "Not tested",
    }
    valid_ip = validate_scanner_ip(scanner_ip)
    if not valid_ip:
        result["udp_msg"] = "Invalid IPv4 address"
        result["rtsp_msg"] = "Invalid IPv4 address"
        return result

    # 1. Test UDP 50536 virtual serial (MDL query)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_sock.settimeout(timeout)
        reply = ""
        for _ in range(2):
            udp_sock.sendto(b"MDL\r", (valid_ip, udp_port))
            try:
                data, _ = udp_sock.recvfrom(4096)
                reply = data.decode("latin-1", errors="ignore").strip()
                if reply:
                    break
            except socket.timeout:
                continue
        if reply:
            model = reply.split(",", 1)[1].strip() if "," in reply else reply
            result["udp_ok"] = True
            result["udp_msg"] = f"OK ({model})"
        else:
            result["udp_msg"] = f"No reply on UDP {udp_port} (check IP, scanner Wi-Fi, or UFW)"
    except OSError as err:
        result["udp_msg"] = f"Error: {err}"
    finally:
        udp_sock.close()

    # 2. Test TCP 554 RTSP audio endpoint
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_sock.settimeout(timeout)
        tcp_sock.connect((valid_ip, rtsp_port))
        req = (
            f"OPTIONS rtsp://{valid_ip}/au:scanner.au RTSP/1.0\r\n"
            f"CSeq: 1\r\nUser-Agent: LinScan\r\n\r\n"
        )
        tcp_sock.sendall(req.encode("ascii"))
        status, _, _ = read_rtsp_response(tcp_sock, timeout=timeout)
        if status == 200:
            result["rtsp_ok"] = True
            result["rtsp_msg"] = f"OK (RTSP 200 on TCP {rtsp_port})"
        else:
            result["rtsp_msg"] = f"Scanner returned RTSP {status}"
    except OSError as err:
        result["rtsp_msg"] = f"Failed on TCP {rtsp_port}: {err}"
    finally:
        tcp_sock.close()

    return result


def find_uniden_ports() -> list[str]:
    """Prioritize Uniden USB Vendor ID (0x1965) or CDC ACM ports."""
    uniden_ports: list[str] = []
    acm_ports: list[str] = []
    other_ports: list[str] = []

    try:
        for port in list_ports.comports():
            if port.vid == 0x1965 or "UNIDEN" in (port.manufacturer or "").upper():
                uniden_ports.append(port.device)
            elif "ttyACM" in port.device:
                acm_ports.append(port.device)
            elif "ttyUSB" in port.device:
                other_ports.append(port.device)
    except Exception as err:
        logging.warning("Port enumeration via list_ports failed: %s", err)

    discovered = uniden_ports + sorted(acm_ports) + sorted(other_ports)
    if not discovered:
        discovered = sorted(glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*"))
    return discovered


def clean_text_for_log(text: str) -> str:
    """Strip non-printable ASCII characters for clean UI rendering and CSV export."""
    return "".join(c for c in text if 0x20 <= ord(c) <= 0x7E).strip()


def clean_uniden_lcd(text: str) -> str:
    """Replace proprietary Uniden hardware LCD glyphs with spaces."""
    return "".join(c if 0x20 <= ord(c) <= 0x7E else " " for c in text)


def sanitize_filename_token(text: str, fallback: str = "UNK") -> str:
    """Convert channel/department text into a filesystem-safe token."""
    cleaned = SAFE_FILENAME_REGEX.sub("_", clean_text_for_log(text)).strip("_")
    return cleaned[:28] if cleaned else fallback


def is_status_line(text: str) -> bool:
    """Identify and filter out scanner status banners, modes, and metadata."""
    clean_upper = text.upper().strip()
    if not clean_upper or len(clean_upper) <= 1:
        return True
    if clean_upper.startswith(("F0:", "S0:")):
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


def compute_mulaw_vu(mulaw_bytes: bytes) -> int:
    """Compute a 0-5 VU meter level directly from 8-bit ITU-T G.711 mu-law audio bytes."""
    if not mulaw_bytes:
        return 0
    # In mu-law, invert bits and mask sign bit (0x7F) to get logarithmic amplitude (0..127)
    peak = max((~b & 0x7F) for b in mulaw_bytes[::4])
    if peak < 18:
        return 0
    if peak < 40:
        return 1
    if peak < 62:
        return 2
    if peak < 84:
        return 3
    if peak < 105:
        return 4
    return 5


def classify_agency_tag(dept: str, chan: str) -> str:
    """Return Treeview color tag for public safety / utility categories."""
    combo_text = f"{dept} {chan}".upper()
    if any(x in combo_text for x in ("POLICE", "LAW", "SHERIFF", "STATE POLICE", "POST 81", "MSP", "PD", "TROOP")):
        return "law"
    if "FIRE" in combo_text or "FD" in combo_text.split():
        return "fire"
    if any(x in combo_text for x in ("EMS", "AMBULANCE", "HOSPITAL", "MEDICAL", "FIRST RESPONDERS", "MED")):
        return "ems"
    if any(x in combo_text for x in ("ROAD", "PUBLIC WORKS", "DPW", "COMMISSION", "TRANSIT")):
        return "works"
    if any(x in combo_text for x in ("NATURAL RES", "PARK", "DNR", "FOREST", "FISH AND WILDLIFE")):
        return "dnr"
    return "default"


class ScrollCatcher:
    """Stitches scrolling LCD text strings across serial poll cycles."""

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

        for shift in (1, 2, 3):
            if len(last_rem) > shift and curr_rem.startswith(last_rem[shift:]):
                tail = curr_rem[len(last_rem) - shift:]
                if tail:
                    self.full_text += tail
                    self.last_seen = current
                    return self.full_text

        if self.full_text.startswith(current):
            self.last_seen = current
            return self.full_text

        self.full_text = self.last_seen = current
        return self.full_text


class SerialManager(threading.Thread):
    """
    Dedicated background control worker thread.
    Defaults strictly to USB Serial (/dev/ttyACM* or /dev/ttyUSB*) and supports
    explicit, thread-safe switching to Wi-Fi UDP (port 50536) with heartbeat
    timeout detection, poll backoff, and multi-packet XML reassembly.
    """

    def __init__(
        self,
        data_queue: queue.Queue,
        scanner_ip: str = "",
        prefer_udp: bool = False,
        udp_port: int = UDP_SCANNER_PORT,
    ):
        super().__init__(daemon=True)
        self.data_queue = data_queue
        self.cmd_queue: queue.Queue[bytes] = queue.Queue()
        self.stop_event = threading.Event()
        self._reconnect_event = threading.Event()
        self._transport_lock = threading.Lock()
        self.ser: serial.Serial | None = None
        self.udp_sock: socket.socket | None = None
        self.scanner_ip = scanner_ip.strip()
        self.prefer_udp = bool(prefer_udp)
        self.udp_port = udp_port
        self._active_ip = self.scanner_ip
        self._active_udp_port = self.udp_port
        self.serial_buffer = b""
        self.udp_buffer = b""
        self.last_udp_rx = 0.0
        self.udp_rx_bytes = 0
        self.udp_warned = False
        self.udp_reconnect_after = 30.0
        self.udp_verified = False

    def configure_transport(self, scanner_ip: str, prefer_udp: bool, udp_port: int = UDP_SCANNER_PORT):
        """Thread-safely switch between USB Serial and Wi-Fi UDP transport."""
        with self._transport_lock:
            self.scanner_ip = scanner_ip.strip()
            self.prefer_udp = bool(prefer_udp)
            self.udp_port = udp_port
        self._reconnect_event.set()

    def send_cmd(self, cmd: bytes):
        """Enqueue a command to be sent asynchronously to the scanner."""
        self.cmd_queue.put(cmd)

    def _emit_link(self, badge_text: str, badge_color: str, status_text: str | None = None, status_color: str | None = None):
        self.data_queue.put(("LINK", (badge_text, badge_color)))
        if status_text is not None and status_color is not None:
            self.data_queue.put(("STATUS", (status_text, status_color)))

    def _write_raw(self, payload: bytes):
        if self.udp_sock and self._active_ip:
            self.udp_sock.sendto(payload, (self._active_ip, self._active_udp_port))
        elif self.ser and self.ser.is_open:
            self.ser.write(payload)

    def _sync_clock(self):
        now = datetime.datetime.now()
        dst_flag = 1 if time.localtime().tm_isdst > 0 else 0
        dtm_cmd = f"DTM,{dst_flag},{now.strftime('%Y,%m,%d,%H,%M,%S')}\r".encode("ascii")
        self._write_raw(dtm_cmd)

    def _wait_retry(self, seconds: float = 1.5):
        """Pause before retrying, waking immediately on stop or mode switch."""
        self._reconnect_event.wait(timeout=seconds)

    def _drain_buffer_lines(self, buf: bytes) -> tuple[list[str], bytes]:
        """Split complete CR-terminated scanner lines while keeping partial XML chunks."""
        if len(buf) > 16384:
            buf = buf[-4096:]
        lines: list[str] = []
        while b"\r" in buf:
            raw_line, buf = buf.split(b"\r", 1)
            line = raw_line.decode("latin-1", errors="ignore").strip()
            if line:
                lines.append(line)
        return lines, buf

    def run(self):
        poll_timer = 0.0
        poll_cycle = 0
        poll_map = {3: b"GSI\r", 9: b"GSI\r", 14: b"GSI\r", 5: b"VOL\r", 10: b"SQL\r", 0: b"CLC\r"}

        while not self.stop_event.is_set():
            if self._reconnect_event.is_set():
                self._reconnect_event.clear()
                self._close_transports()

            with self._transport_lock:
                use_udp = self.prefer_udp
                target_ip = self.scanner_ip
                target_port = self.udp_port

            connected = (self.ser is not None and self.ser.is_open) or (self.udp_sock is not None)
            if not connected:
                if use_udp:
                    if not target_ip:
                        self._emit_link("WIFI: NO IP", "#FF0033", "SET WIFI IP FIRST", "#FF0033")
                        self._wait_retry(1.5)
                        continue
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(0.05)
                        self.udp_sock = sock
                        self._active_ip = target_ip
                        self._active_udp_port = target_port
                        self.udp_buffer = b""
                        self.udp_warned = False
                        self.last_udp_rx = time.time()
                        self.udp_verified = False
                        self._write_raw(b"STS\r")
                        self._emit_link("WIFI: WAIT", "#FFFF00", f"WIFI WAIT ({target_ip})", "#FFFF00")
                    except OSError as err:
                        logging.warning("UDP transport init failed: %s", err)
                        self.udp_sock = None
                        self._emit_link("WIFI: ERROR", "#FF0033", "WIFI INIT FAILED", "#FF0033")
                        self._wait_retry(1.5)
                        continue
                else:
                    ports = find_uniden_ports()
                    if not ports:
                        self._emit_link("USB: NONE", "#FF0033", "NO USB DETECTED", "#FF0033")
                        self._wait_retry(1.5)
                        continue

                    last_err_msg = ""
                    for p in ports:
                        try:
                            self.ser = serial.Serial(p, BAUD_RATE, timeout=0.05, write_timeout=0.2)
                            self.serial_buffer = b""
                            port_name = Path(p).name
                            self._emit_link(f"USB: {port_name}", "#39FF14", f"CONNECTED ({port_name})", "#39FF14")
                            self._sync_clock()
                            break
                        except Exception as err:
                            logging.warning("Serial connection attempt failed on %s: %s", p, err)
                            if isinstance(err, PermissionError) or "permission denied" in str(err).lower():
                                last_err_msg = f"USB PERM DENIED ({Path(p).name})"
                            else:
                                last_err_msg = f"USB BUSY/ERR ({Path(p).name})"
                            self.ser = None

                    if not self.ser:
                        if last_err_msg:
                            self._emit_link("USB: ERROR", "#FF0033", last_err_msg, "#FF0033")
                        self._wait_retry(1.5)
                        continue

            while not self.cmd_queue.empty():
                try:
                    cmd = self.cmd_queue.get_nowait()
                    self._write_raw(cmd)
                    time.sleep(0.035)
                except Exception as err:
                    logging.error("Command write failed: %s", err)
                    self._close_transports()
                    break

            if not (self.ser and self.ser.is_open) and not self.udp_sock:
                continue

            now = time.time()

            # Pace polling cleanly: 140ms on USB, 180ms on healthy Wi-Fi, 1.0s backoff when Wi-Fi silent
            if self.udp_sock:
                poll_interval = 1.0 if (self.udp_warned or not self.udp_verified) else 0.30
            else:
                poll_interval = 0.14

            if now - poll_timer >= poll_interval:
                poll_timer = now
                try:
                    if self.udp_sock and (self.udp_warned or not self.udp_verified):
                        # Lightweight probe while waiting for Wi-Fi dongle to respond
                        self._write_raw(b"STS\r")
                    else:
                        poll_cycle = (poll_cycle + 1) % 15
                        self._write_raw(poll_map.get(poll_cycle, b"STS\r"))
                except Exception as err:
                    logging.warning("Poll write error: %s", err)
                    self._close_transports()
                    continue

            if self.udp_sock:
                try:
                    while True:
                        raw_pkt, _ = self.udp_sock.recvfrom(8192)
                        self.last_udp_rx = time.time()
                        self.udp_rx_bytes += len(raw_pkt)
                        if self.udp_warned or not self.udp_verified:
                            self.udp_warned = False
                            self.udp_verified = True
                            self._sync_clock()
                            self._emit_link(
                                f"WIFI: {self._active_ip}", "#00FFFF",
                                f"WIFI UDP ({self._active_ip})", "#00FFFF",
                            )
                        self.udp_buffer += raw_pkt
                        lines, self.udp_buffer = self._drain_buffer_lines(self.udp_buffer)
                        for line in lines:
                            self.data_queue.put(("RAW", line))
                except socket.timeout:
                    silence = time.time() - self.last_udp_rx
                    if not self.udp_warned and silence > UDP_NO_REPLY_TIMEOUT_SEC:
                        self.udp_warned = True
                        self._emit_link(
                            f"WIFI: NO REPLY", "#FFA500",
                            f"WIFI NO REPLY ({self._active_ip})", "#FFA500",
                        )
                    elif silence > self.udp_reconnect_after:
                        # Recreate UDP socket in case local network interface changed
                        logging.info("Wi-Fi UDP silent for %.0fs; recycling socket", silence)
                        self._close_transports(emit_disconnected=False)
                        self._emit_link("WIFI: RETRYING", "#FFA500", f"WIFI NO REPLY ({self._active_ip})", "#FFA500")
                        self._wait_retry(1.0)
                        continue
                except OSError as err:
                    logging.warning("UDP read error: %s", err)
                    self._close_transports()
            elif self.ser and self.ser.is_open:
                try:
                    if self.ser.in_waiting:
                        chunk = self.ser.read(self.ser.in_waiting)
                        self.serial_buffer += chunk
                        lines, self.serial_buffer = self._drain_buffer_lines(self.serial_buffer)
                        for line in lines:
                            self.data_queue.put(("RAW", line))
                except Exception as err:
                    logging.warning("Serial read error: %s", err)
                    self._close_transports()

            time.sleep(0.012)

        self._close_transports()

    def _close_transports(self, emit_disconnected: bool = True):
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass
        self.ser = None
        if self.udp_sock:
            try:
                self.udp_sock.close()
            except Exception:
                pass
        self.udp_sock = None
        self.serial_buffer = b""
        self.udp_buffer = b""
        if emit_disconnected:
            self._emit_link("LINK: OFF", "#FF0033", "DISCONNECTED", "#FF0033")

    def stop(self):
        self.stop_event.set()
        self._reconnect_event.set()
        if self.is_alive():
            self.join(timeout=1.5)


class USBRecordingEngine(threading.Thread):
    """Captures and filters audio via local ALSA/PulseAudio inputs."""

    def __init__(self, mp3_path: Path):
        super().__init__(daemon=True)
        self.mp3_path = mp3_path
        self.stop_event = threading.Event()
        self.ffmpeg_proc: subprocess.Popen | None = None
        self.start_time = datetime.datetime.now()

    def run(self):
        vox_filter = (
            "silenceremove=start_periods=1:start_duration=0:start_threshold=-45dB:"
            "stop_periods=-1:stop_duration=2:stop_threshold=-45dB"
        )
        norm_filter = "dynaudnorm=f=150:g=15"

        ffmpeg_cmd = [
            "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "warning", "-stats", "-y",
            "-f", "pulse", "-i", "default",
            "-af", f"aresample=async=1,{vox_filter},{norm_filter}",
            "-c:a", "libmp3lame", "-b:a", "64k", str(self.mp3_path)
        ]

        try:
            self.ffmpeg_proc = subprocess.Popen(
                ffmpeg_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            self._monitor_recording()
        except OSError as err:
            logging.error("Failed to start USB recording process: %s", err)
        finally:
            self.cleanup()

    def _monitor_recording(self):
        if not self.ffmpeg_proc or not self.ffmpeg_proc.stderr:
            return
        buf = ""
        try:
            while not self.stop_event.is_set():
                chunk = self.ffmpeg_proc.stderr.read(64)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", errors="ignore")
                while "\r" in buf or "\n" in buf:
                    parts = re.split(r"[\r\n]", buf, maxsplit=1)
                    buf = parts[1] if len(parts) > 1 else ""
        except OSError:
            pass

    def stop_async(self):
        """Non-blocking stop so the Tkinter main thread never stalls."""
        self.stop_event.set()
        if self.ffmpeg_proc:
            try:
                self.ffmpeg_proc.terminate()
            except Exception:
                pass

    def stop(self):
        self.stop_async()
        if self.is_alive():
            self.join(timeout=2.5)

    def cleanup(self):
        if self.ffmpeg_proc:
            try:
                self.ffmpeg_proc.wait(timeout=2)
            except Exception:
                try:
                    self.ffmpeg_proc.kill()
                except Exception:
                    pass
            self.ffmpeg_proc = None

        if self.mp3_path.exists():
            try:
                if self.mp3_path.stat().st_size < 10000:
                    self.mp3_path.unlink()
                else:
                    new_name = (
                        f"Session_USB_{self.start_time.strftime('%Y-%m-%d_%I-%M-%S%p')}"
                        f"_to_{datetime.datetime.now().strftime('%I-%M-%S%p')}.mp3"
                    )
                    new_path = self.mp3_path.parent / new_name
                    if new_path.exists():
                        new_path.unlink()
                    self.mp3_path.rename(new_path)
            except OSError as err:
                logging.warning("Error cleaning up USB recording file: %s", err)


class RTSPAudioEngine(threading.Thread):
    """
    ProScan-grade Uniden BCD536HP / SDS200 Wi-Fi RTSP audio engine.
    Features:
      - Full RTSP 1.0 response framing & status validation
      - Even/odd RTP/RTCP UDP port pair (UFW-friendly default 50538-50539)
      - Proper Session-authenticated OPTIONS keep-alive & TEARDOWN
      - Automatic stall detection & exponential-backoff reconnect
      - 0.5s rolling pre-roll audio buffer so per-call clips don't clip first syllables
      - Live speaker monitoring (ffplay) toggleable independently of MP3 recording
    """

    def __init__(
        self,
        scanner_ip: str,
        session_mp3_path: Path | None = None,
        live_monitor: bool = False,
        rtsp_port: int = 554,
        preferred_rtp_port: int = DEFAULT_RTP_CLIENT_PORT,
        stall_timeout: float = RTSP_STALL_TIMEOUT_SEC,
        status_callback=None,
    ):
        super().__init__(daemon=True)
        self.ip = scanner_ip.strip()
        self.rtsp_port = rtsp_port
        self.preferred_rtp_port = preferred_rtp_port
        self.stall_timeout = stall_timeout
        self.status_callback = status_callback

        self.mp3_path: Path | None = session_mp3_path
        self.live_monitor = live_monitor
        self.stop_event = threading.Event()

        self.tcp_sock: socket.socket | None = None
        self.udp_sock: socket.socket | None = None
        self.rtcp_sock: socket.socket | None = None
        self.session_id = ""
        self.cseq = 1

        self.proc_lock = threading.Lock()
        self.ffmpeg_proc: subprocess.Popen | None = None
        self.monitor_proc: subprocess.Popen | None = None
        self.clip_proc: subprocess.Popen | None = None
        self.clip_path: Path | None = None

        # 0.5s rolling pre-roll buffer (8000 bytes/sec * 0.5s = 4000 bytes)
        self.pre_roll: deque[bytes] = deque()
        self.pre_roll_bytes = 0

        self.current_vu_level = 0
        self.last_vu_time = 0.0
        self.rtp_rx_bytes = 0
        self.audio_state = "CONNECTING"
        self.start_time = datetime.datetime.now()

    def _notify_status(self, state: str):
        self.audio_state = state
        if self.status_callback:
            try:
                self.status_callback(state)
            except Exception:
                pass

    def _spawn_session_encoder_unlocked(self):
        if not self.mp3_path or not shutil.which("ffmpeg"):
            return
        audio_filter = (
            "volume=3.0,"
            "silenceremove=start_periods=1:start_duration=0.05:start_threshold=-42dB:"
            "stop_periods=-1:stop_duration=1.0:stop_threshold=-42dB,"
            "dynaudnorm=f=150:g=15"
        )
        ffmpeg_cmd = [
            "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "warning", "-y",
            "-f", "mulaw", "-ar", "8000", "-ac", "1", "-i", "pipe:0",
            "-af", audio_filter, "-c:a", "libmp3lame", "-b:a", "64k", str(self.mp3_path)
        ]
        try:
            self.ffmpeg_proc = subprocess.Popen(
                ffmpeg_cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except OSError as err:
            logging.error("Failed to start RTSP FFmpeg encoder: %s", err)
            self.ffmpeg_proc = None

    def _spawn_monitor_unlocked(self):
        if not self.live_monitor or not shutil.which("ffplay"):
            return
        if self.monitor_proc and self.monitor_proc.poll() is None:
            return
        mon_cmd = [
            "ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet",
            "-fflags", "nobuffer", "-flags", "low_delay",
            "-f", "mulaw", "-ar", "8000", "-ac", "1", "-i", "pipe:0"
        ]
        try:
            self.monitor_proc = subprocess.Popen(
                mon_cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except OSError as err:
            logging.warning("Failed to start ffplay live monitor: %s", err)
            self.monitor_proc = None

    def _close_proc(self, proc: subprocess.Popen | None):
        if not proc:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.wait(timeout=1.5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def set_live_monitor(self, enabled: bool):
        """Toggle live speaker playback without interrupting RTSP stream."""
        with self.proc_lock:
            self.live_monitor = enabled
            if enabled:
                self._spawn_monitor_unlocked()
            else:
                proc = self.monitor_proc
                self.monitor_proc = None
                self._close_proc(proc)

    def start_session_recording(self, mp3_path: Path):
        """Attach session MP3 recording to an already-running RTSP stream."""
        with self.proc_lock:
            if self.ffmpeg_proc and self.ffmpeg_proc.poll() is None:
                return
            self.mp3_path = mp3_path
            self.start_time = datetime.datetime.now()
            self._spawn_session_encoder_unlocked()

    def stop_session_recording(self):
        """Detach and finalize session MP3 recording while keeping live monitor active."""
        with self.proc_lock:
            proc = self.ffmpeg_proc
            self.ffmpeg_proc = None
            path_to_finalize = self.mp3_path
            self.mp3_path = None
        self._close_proc(proc)
        self._finalize_session_file(path_to_finalize)

    def start_call_clip(self, clip_path: Path):
        """Start capturing an individual per-transmission MP3 clip with pre-roll buffer."""
        with self.proc_lock:
            self._close_clip_unlocked()
            if not shutil.which("ffmpeg"):
                return
            self.clip_path = clip_path
            cmd = [
                "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
                "-f", "mulaw", "-ar", "8000", "-ac", "1", "-i", "pipe:0",
                "-af", "volume=3.0,dynaudnorm=f=150:g=15",
                "-c:a", "libmp3lame", "-b:a", "64k", str(clip_path)
            ]
            try:
                self.clip_proc = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
                # Flush 0.5s pre-roll buffer so opening syllable isn't clipped
                if self.clip_proc.stdin and self.pre_roll:
                    self.clip_proc.stdin.write(b"".join(self.pre_roll))
                    self.clip_proc.stdin.flush()
            except OSError as err:
                logging.warning("Failed to start per-call clip encoder: %s", err)
                self.clip_proc = None

    def finalize_call_clip(self) -> Path | None:
        """Close the active per-transmission MP3 clip and return its path if valid."""
        with self.proc_lock:
            return self._close_clip_unlocked()

    def _close_clip_unlocked(self) -> Path | None:
        saved_path = self.clip_path
        proc = self.clip_proc
        self.clip_proc = None
        self.clip_path = None
        self._close_proc(proc)
        if saved_path and saved_path.exists():
            try:
                if saved_path.stat().st_size < 2048:
                    saved_path.unlink()
                    return None
                return saved_path
            except OSError:
                return None
        return None

    def _append_pre_roll(self, chunk: bytes):
        self.pre_roll.append(chunk)
        self.pre_roll_bytes += len(chunk)
        while self.pre_roll_bytes > PRE_ROLL_MAX_BYTES and len(self.pre_roll) > 1:
            dropped = self.pre_roll.popleft()
            self.pre_roll_bytes -= len(dropped)

    def _feed_audio_chunk(self, audio_chunk: bytes):
        self.current_vu_level = compute_mulaw_vu(audio_chunk)
        self.last_vu_time = time.time()
        self.rtp_rx_bytes += len(audio_chunk)

        with self.proc_lock:
            self._append_pre_roll(audio_chunk)

            if self.ffmpeg_proc and self.ffmpeg_proc.stdin:
                try:
                    self.ffmpeg_proc.stdin.write(audio_chunk)
                    self.ffmpeg_proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    logging.warning("Session FFmpeg pipe broke; restarting encoder")
                    self._close_proc(self.ffmpeg_proc)
                    self.ffmpeg_proc = None
                    if self.mp3_path:
                        self._spawn_session_encoder_unlocked()

            if self.monitor_proc and self.monitor_proc.stdin:
                try:
                    self.monitor_proc.stdin.write(audio_chunk)
                    self.monitor_proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    self._close_proc(self.monitor_proc)
                    self.monitor_proc = None

            if self.clip_proc and self.clip_proc.stdin:
                try:
                    self.clip_proc.stdin.write(audio_chunk)
                    self.clip_proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    self._close_proc(self.clip_proc)
                    self.clip_proc = None

    def _send_teardown_locked_worker(self):
        """Send RFC-compliant Session-authenticated TEARDOWN from the worker thread."""
        if not self.tcp_sock or not self.session_id:
            return
        try:
            self.cseq += 1
            req = (
                f"TEARDOWN rtsp://{self.ip}/au:scanner.au/ RTSP/1.0\r\n"
                f"CSeq: {self.cseq}\r\n"
                f"Session: {self.session_id}\r\n"
                f"User-Agent: LinScan\r\n\r\n"
            )
            self.tcp_sock.settimeout(1.5)
            self.tcp_sock.sendall(req.encode("ascii"))
            try:
                self.tcp_sock.recv(512)
            except OSError:
                pass
        except OSError:
            pass
        finally:
            self.session_id = ""

    def run(self):
        with self.proc_lock:
            if self.mp3_path:
                self._spawn_session_encoder_unlocked()
            if self.live_monitor:
                self._spawn_monitor_unlocked()

        backoff = 2.0
        while not self.stop_event.is_set():
            try:
                self._notify_status("CONNECTING")
                self.connect_and_stream()
                backoff = 2.0
            except Exception as err:
                if not self.stop_event.is_set():
                    err_text = str(err)
                    if "453" in err_text or "503" in err_text or "BUSY" in err_text.upper():
                        self._notify_status("STREAM BUSY")
                    else:
                        self._notify_status("RECONNECTING")
                    logging.warning("RTSP audio interrupted (%s). Retrying in %.0fs...", err, backoff)
                    self._send_teardown_locked_worker()
                    self.close_sockets()
                    self.stop_event.wait(timeout=backoff)
                    backoff = min(backoff * 1.5, 10.0)
        self.cleanup()

    def connect_and_stream(self):
        self.udp_sock, self.rtcp_sock, rtp_port, rtcp_port = bind_rtp_rtcp_pair(self.preferred_rtp_port)
        self.udp_sock.settimeout(1.0)
        self.rtcp_sock.settimeout(0.0)  # Non-blocking drain to prevent ICMP Port Unreachable

        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp_sock.settimeout(5.0)
        self.tcp_sock.connect((self.ip, self.rtsp_port))

        base_url = f"rtsp://{self.ip}/au:scanner.au"
        self.cseq = 1
        self.session_id = ""

        # 1. OPTIONS
        self.tcp_sock.sendall(
            f"OPTIONS {base_url} RTSP/1.0\r\nCSeq: {self.cseq}\r\nUser-Agent: LinScan\r\n\r\n".encode("ascii")
        )
        status, _, _ = read_rtsp_response(self.tcp_sock, timeout=5.0)
        if status != 200:
            raise OSError(f"RTSP OPTIONS failed with status {status}")
        self.cseq += 1

        # 2. DESCRIBE (parse SDP track control URL if provided)
        self.tcp_sock.sendall(
            f"DESCRIBE {base_url} RTSP/1.0\r\nCSeq: {self.cseq}\r\nUser-Agent: LinScan\r\nAccept: application/sdp\r\n\r\n".encode("ascii")
        )
        status, _, sdp_body = read_rtsp_response(self.tcp_sock, timeout=5.0)
        if status != 200:
            raise OSError(f"RTSP DESCRIBE failed with status {status}")
        self.cseq += 1

        setup_url = f"{base_url}/trackID=1"
        ctrl_matches = SDP_CONTROL_REGEX.findall(sdp_body)
        for ctrl in reversed(ctrl_matches):
            ctrl = ctrl.strip()
            if ctrl and ctrl != "*":
                setup_url = ctrl if ctrl.lower().startswith("rtsp://") else f"{base_url}/{ctrl.lstrip('/')}"
                break

        # 3. SETUP (Uniden BCD536HP requires UDP RTP/AVP unicast with even/odd client_port)
        setup_req = (
            f"SETUP {setup_url} RTSP/1.0\r\n"
            f"CSeq: {self.cseq}\r\n"
            f"User-Agent: LinScan\r\n"
            f"Transport: RTP/AVP;unicast;client_port={rtp_port}-{rtcp_port}\r\n\r\n"
        )
        self.tcp_sock.sendall(setup_req.encode("ascii"))
        status, setup_hdrs, _ = read_rtsp_response(self.tcp_sock, timeout=5.0)
        if status != 200:
            raise OSError(f"RTSP SETUP rejected (status {status} - another app may hold stream)")
        self.cseq += 1

        sess_match = SESSION_REGEX.search(setup_hdrs)
        self.session_id = sess_match.group(1).strip() if sess_match else ""

        keepalive_interval = RTSP_KEEPALIVE_DEFAULT_SEC
        to_match = SESSION_TIMEOUT_REGEX.search(setup_hdrs)
        if to_match:
            srv_timeout = int(to_match.group(1))
            keepalive_interval = max(5.0, min(RTSP_KEEPALIVE_DEFAULT_SEC, srv_timeout * 0.5))

        port_match = SERVER_PORT_REGEX.search(setup_hdrs)
        server_port = int(port_match.group(1)) if port_match else 5004

        # 4. PLAY
        play_req = (
            f"PLAY {base_url}/ RTSP/1.0\r\n"
            f"CSeq: {self.cseq}\r\n"
            f"User-Agent: LinScan\r\n"
            f"Session: {self.session_id}\r\n"
            f"Range: npt=0.000-\r\n\r\n"
        )
        self.tcp_sock.sendall(play_req.encode("ascii"))
        status, _, _ = read_rtsp_response(self.tcp_sock, timeout=5.0)
        if status != 200:
            raise OSError(f"RTSP PLAY rejected (status {status})")
        self.cseq += 1

        # Punch NAT/UFW conntrack holes for RTP & RTCP
        for p in {server_port, 5000, 5004, 5006}:
            try:
                self.udp_sock.sendto(b"\x80\x00\x00\x00", (self.ip, p))
                self.rtcp_sock.sendto(b"\x80\xc9\x00\x01\x00\x00\x00\x00", (self.ip, p + 1))
            except OSError:
                pass

        self._notify_status("CONNECTED")
        last_ping = time.time()
        last_rtp = time.time()

        while not self.stop_event.is_set():
            now = time.time()
            if now - last_ping >= keepalive_interval:
                ping_req = (
                    f"OPTIONS {base_url} RTSP/1.0\r\n"
                    f"CSeq: {self.cseq}\r\n"
                    f"Session: {self.session_id}\r\n"
                    f"User-Agent: LinScan\r\n\r\n"
                )
                self.tcp_sock.sendall(ping_req.encode("ascii"))
                ping_status, _, _ = read_rtsp_response(self.tcp_sock, timeout=4.0)
                if ping_status != 200:
                    raise OSError(f"RTSP keep-alive failed (status {ping_status})")
                self.cseq += 1
                last_ping = time.time()

            # Drain any incoming RTCP packets quietly
            if self.rtcp_sock:
                try:
                    self.rtcp_sock.recvfrom(1024)
                except OSError:
                    pass

            try:
                data, _ = self.udp_sock.recvfrom(2048)
                if len(data) >= 12 and (data[0] >> 6) == 2:
                    cc = data[0] & 0x0F
                    has_ext = bool(data[0] & 0x10)
                    has_pad = bool(data[0] & 0x20)
                    payload_offset = 12 + (cc * 4)

                    if has_ext and len(data) >= payload_offset + 4:
                        ext_words = int.from_bytes(data[payload_offset + 2:payload_offset + 4], "big")
                        payload_offset += 4 + (ext_words * 4)

                    payload_end = len(data)
                    if has_pad and payload_end > payload_offset:
                        pad_len = data[-1]
                        if pad_len < (payload_end - payload_offset):
                            payload_end -= pad_len

                    if payload_offset < payload_end:
                        last_rtp = time.time()
                        self._feed_audio_chunk(data[payload_offset:payload_end])
            except socket.timeout:
                if time.time() - last_rtp > self.stall_timeout:
                    raise OSError(f"No RTP audio packets for {self.stall_timeout:.0f}s")
                continue

        self._send_teardown_locked_worker()
        self.close_sockets()

    def stop_async(self):
        """Signal the RTSP worker thread to tear down cleanly and exit."""
        self.stop_event.set()

    def stop(self):
        self.stop_async()
        if self.is_alive():
            self.join(timeout=3.0)

    def close_sockets(self):
        for sock in (self.tcp_sock, self.udp_sock, self.rtcp_sock):
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass
        self.tcp_sock = self.udp_sock = self.rtcp_sock = None

    def _finalize_session_file(self, path: Path | None):
        if path and path.exists():
            try:
                if path.stat().st_size < 20000:
                    path.unlink()
                else:
                    new_name = (
                        f"Session_VOX_{self.start_time.strftime('%Y-%m-%d_%I-%M-%S%p')}"
                        f"_to_{datetime.datetime.now().strftime('%I-%M-%S%p')}.mp3"
                    )
                    new_path = path.parent / new_name
                    if new_path.exists():
                        new_path.unlink()
                    path.rename(new_path)
            except OSError as err:
                logging.warning("Error finalizing RTSP recording: %s", err)

    def cleanup(self):
        self._send_teardown_locked_worker()
        self.close_sockets()
        self.finalize_call_clip()
        with self.proc_lock:
            ff_proc, mon_proc = self.ffmpeg_proc, self.monitor_proc
            path_to_finalize = self.mp3_path
            self.ffmpeg_proc = self.monitor_proc = None
            self.mp3_path = None
        self._close_proc(ff_proc)
        self._close_proc(mon_proc)
        self._finalize_session_file(path_to_finalize)
        self._notify_status("OFF")


class LinScanWebServer:
    """Embedded HTTP server exposing live HTML5 LCD and JSON telemetry."""

    def __init__(self, state_provider, port: int = 8080, key_handler=None):
        self.state_provider = state_provider; self.key_handler = key_handler
        self.port = port
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> bool:
        if self.httpd is not None:
            return True
        provider = self.state_provider; key_cb = self.key_handler

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format: str, *args: Any):
                pass

            def do_GET(self):
                if self.path == "/api/state":
                    payload = json.dumps(provider()).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    self.wfile.write(payload)
                    return

                html = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>LinScan-536 Web Server</title>
<style>
body { background:#0a0a0a; color:#eee; font-family:monospace; margin:20px; }
.lcd { background:#39FF14; color:#000; padding:16px; border-radius:10px; width:440px;
       font-size:18px; font-weight:bold; white-space:pre; line-height:1.35; margin-bottom:16px; }
table { border-collapse:collapse; width:100%; font-family:sans-serif; font-size:13px; }
th, td { border:1px solid #333; padding:6px 10px; text-align:left; }
th { background:#222; color:#00FFFF; }
</style></head><body>
<h2>LinScan-536 Live Web Server <span id="st" style="color:#39FF14;font-size:14px;"></span></h2>
<div class="lcd" id="lcd">Connecting...</div>
<div style="margin-bottom:12px;"><button onclick="sk('A')" style="background:#222;color:#0ff;border:1px solid #444;padding:6px 10px;margin:2px;cursor:pointer;font-weight:bold;">SYS</button><button onclick="sk('B')" style="background:#222;color:#0ff;border:1px solid #444;padding:6px 10px;margin:2px;cursor:pointer;font-weight:bold;">DEPT</button><button onclick="sk('C')" style="background:#222;color:#0ff;border:1px solid #444;padding:6px 10px;margin:2px;cursor:pointer;font-weight:bold;">CH</button><button onclick="sk('L')" style="background:#222;color:#0ff;border:1px solid #444;padding:6px 10px;margin:2px;cursor:pointer;font-weight:bold;">AVOID</button><button onclick="sk('<')" style="background:#222;color:#0ff;border:1px solid #444;padding:6px 10px;margin:2px;cursor:pointer;font-weight:bold;">◀</button><button onclick="sk('>')" style="background:#222;color:#0ff;border:1px solid #444;padding:6px 10px;margin:2px;cursor:pointer;font-weight:bold;">▶</button><button onclick="sk('E')" style="background:#222;color:#0ff;border:1px solid #444;padding:6px 10px;margin:2px;cursor:pointer;font-weight:bold;">E</button></div>
<table><thead><tr><th>Time</th><th>System</th><th>Department</th><th>Channel</th><th>Freq/Mod</th><th>TGID</th><th>UID</th><th>Dur</th></tr></thead>
<tbody id="hist"></tbody></table>
<script>
async function poll(){
  try {
    const r = await fetch('/api/state');
    const d = await r.json();
    document.getElementById('st').textContent = `[${d.link} | ${d.status} | ${d.sig}]`;
    document.getElementById('lcd').textContent = d.lcd.join('\\n');
    document.getElementById('hist').innerHTML = d.history.map(row =>
      `<tr>${row.map(c => `<td>${c}</td>`).join('')}</tr>`).join('');
  } catch(e) {}
}
async function sk(k){await fetch('/api/key',{method:'POST',body:k});}
setInterval(poll, 500); poll();
</script></body></html>""".encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html)
            def do_POST(self):
                if self.path == '/api/key' and key_cb:
                    ln = int(self.headers.get('Content-Length', 0))
                    k = self.rfile.read(min(ln, 8)).decode('ascii', 'ignore').strip()
                    if k in {'A','B','C','L','<','>','E','M','Y'}: key_cb(k)
                    self.send_response(204); self.end_headers(); return
                self.send_response(404); self.end_headers()

        try:
            self.httpd = ThreadingHTTPServer(("0.0.0.0", self.port), Handler)
            self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            self.thread.start()
            return True
        except OSError as err:
            logging.error("Web server failed on port %d: %s", self.port, err)
            self.httpd = None
            return False

    def stop(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
                self.httpd.server_close()
            except Exception:
                pass
            self.httpd = None


class VirtualScanner(tk.Tk):
    """Main graphical user interface for LinScan-536 Pro."""

    def __init__(self):
        super().__init__()
        self.title("LinScan-536 Pro")
        self.geometry("1260x830")
        self.minsize(1140, 680)
        self.configure(bg="#050505")

        available_fonts = set(tkfont.families())
        self.mono_family = "DejaVu Sans Mono" if "DejaVu Sans Mono" in available_fonts else "monospace"
        self.sans_family = "DejaVu Sans" if "DejaVu Sans" in available_fonts else "sans-serif"
        self.lcd_font = tkfont.Font(family=self.mono_family, size=17, weight="bold")

        self.rtsp_engine: RTSPAudioEngine | None = None
        self.usb_engine: USBRecordingEngine | None = None
        self.playback_proc: subprocess.Popen | None = None

        self.active_call = False
        self.record_enabled = False
        self.live_listen_enabled = False
        self.usb_record_enabled = False
        self.prefer_udp_control = False  # USB-first default
        self.web_enabled = False
        self.skip_short_calls = False
        self._hidden = {}
        self._last_web_sync = 0.0
        self._last_vu = None
        self.call_store = linscan_pro.CallStore(CONFIG_DIR / 'history.db')

        self.current_uid = ""
        self.current_tgid = ""
        self.current_freq = ""
        self.current_mod = ""
        self.current_clip_path: Path | None = None
        self.scanner_ip = ""
        self.web_port = 8080
        self.retention_days = 7
        self.max_audio_mb = 500
        self.rtp_client_port = DEFAULT_RTP_CLIENT_PORT

        self.vol_dragging = False
        self.sql_dragging = False
        self.last_vol_change = 0.0
        self.last_sql_change = 0.0

        self.catchers = [ScrollCatcher() for _ in range(16)]
        self.log_sys = ScrollCatcher()
        self.log_dept = ScrollCatcher()
        self.log_chan = ScrollCatcher()
        self.latest_gsi: GSITelemetry | None = None

        self.tg_hits: dict[str, int] = {}
        self.call_times: dict[str, float] = {}
        self.uid_aliases: dict[str, str] = {}
        self.uid_hits: dict[str, int] = {}
        self.history_clips: dict[str, str] = {}
        self.current_call_start: float | None = None

        self.lcd_colors = ["#C0C0C0", "#FFA500", "#39FF14", "#00FFFF", "#FFB6C1", "#ADD8E6"]
        self.current_color_idx = 0
        self.last_lcd_snapshot = [""] * 6

        self._web_lock = threading.Lock()
        self._web_snapshot: dict[str, Any] = {
            "link": "USB: INIT",
            "status": "CONNECTING...",
            "sig": "SIG: □ □ □ □ □",
            "lcd": [""] * 6,
            "history": [],
        }

        self.config_file = CONFIG_DIR / "config.json"
        self.uid_file = CONFIG_DIR / "uid_aliases.json"
        self.audio_dir = Path.home() / "LinScan_Audio"
        self.clips_dir = self.audio_dir / "Clips"

        self._last_sig = ""
        self._last_sig_color = ""
        self._last_scan_state = None
        self._last_bg_size = None
        self._rtsp_status_text = "OFF"

        self.has_ffmpeg = shutil.which("ffmpeg") is not None
        self.has_ffplay = shutil.which("ffplay") is not None
        if not self.has_ffmpeg:
            logging.warning("FFmpeg not found in PATH. Audio recording features will be unavailable.")

        self.load_config()
        self.prune_audio_storage()
        self.web_server = LinScanWebServer(self._get_web_state, port=self.web_port, key_handler=self.send_key)
        self._build_ui()
        linscan_pro.restore_history(self)

        self.serial_queue: queue.Queue = queue.Queue()
        self.serial_manager = SerialManager(
            self.serial_queue, scanner_ip=self.scanner_ip, prefer_udp=self.prefer_udp_control
        )
        self.serial_manager.start()

        self.bind_all("<Key>", self.handle_keypress)
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.process_serial_queue()
        self.update_idletasks()
        self.draw_background()

    def load_config(self):
        if self.config_file.exists():
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    raw_ip = str(config.get("scanner_ip", "")).strip()
                    self.scanner_ip = validate_scanner_ip(raw_ip) or ""
                    loaded_color = int(config.get("lcd_color_idx", 0))
                    self.current_color_idx = loaded_color % len(self.lcd_colors)
                    self.prefer_udp_control = bool(config.get("prefer_udp_control", False))
                    self.web_port = int(config.get("web_port", 8080))
                    self.retention_days = int(config.get("retention_days", 7))
                    self.max_audio_mb = int(config.get("max_audio_mb", 500))
                    self.rtp_client_port = int(config.get("rtp_client_port", DEFAULT_RTP_CLIENT_PORT))
                    self.skip_short_calls = bool(config.get("skip_short_calls", False))
            except Exception as e:
                logging.warning("Failed to parse config file: %s", e)
        else:
            self.save_config()

        if self.uid_file.exists():
            try:
                with open(self.uid_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.uid_aliases = {str(k): str(v) for k, v in data.items()}
            except Exception as e:
                logging.warning("Failed to parse UID alias file: %s", e)

    def save_config(self):
        try:
            config = {
                "scanner_ip": self.scanner_ip,
                "lcd_color_idx": self.current_color_idx,
                "prefer_udp_control": self.prefer_udp_control,
                "web_port": self.web_port,
                "retention_days": self.retention_days,
                "max_audio_mb": self.max_audio_mb,
                "rtp_client_port": self.rtp_client_port,
                "skip_short_calls": self.skip_short_calls,
            }
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4)
            with open(self.uid_file, "w", encoding="utf-8") as f:
                json.dump(self.uid_aliases, f, indent=4, sort_keys=True)
        except Exception as e:
            logging.error("Failed to write config file: %s", e)

    def format_uid_display(self, raw_uid: str) -> str:
        uid_clean = raw_uid.strip()
        if not uid_clean:
            return ""
        alias = self.uid_aliases.get(uid_clean)
        return f"{alias} ({uid_clean})" if alias else uid_clean

    def _build_ui(self):
        self.faceplate = tk.Frame(self, bg="#1a1a1a", bd=4, relief=tk.RAISED)
        self.faceplate.pack(fill=tk.X, padx=15, pady=12)

        self.software_panel = tk.Frame(self, bg="#050505")
        self.software_panel.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 12))

        self.vol_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.vol_panel.pack(side=tk.LEFT, fill=tk.Y, padx=18, pady=15)

        for name, to_val in [("VOL", 29), ("SQL", 19)]:
            sub = tk.Frame(self.vol_panel, bg="#1a1a1a")
            sub.pack(side=tk.LEFT, padx=5)
            tk.Label(sub, text=name, fg="#888888", bg="#1a1a1a", font=(self.sans_family, 11, "bold")).pack(pady=(0, 5))
            slider = tk.Scale(
                sub, from_=to_val, to=0, orient=tk.VERTICAL, bg="#111111",
                fg="#39FF14" if name == "VOL" else "#00FFFF",
                troughcolor="#050505", bd=1, highlightthickness=0, relief=tk.SUNKEN,
                activebackground="#2a2a2a", length=180
            )
            slider.pack(fill=tk.Y, expand=True)
            if name == "VOL":
                self.vol_slider = slider
                self.vol_slider.bind("<ButtonPress-1>", lambda e: setattr(self, "vol_dragging", True))
                self.vol_slider.bind("<ButtonRelease-1>", lambda e: self.send_volume())
            else:
                self.sql_slider = slider
                self.sql_slider.bind("<ButtonPress-1>", lambda e: setattr(self, "sql_dragging", True))
                self.sql_slider.bind("<ButtonRelease-1>", lambda e: self.send_squelch())

        self.keypad_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.keypad_panel.pack(side=tk.RIGHT, fill=tk.Y, padx=18, pady=15)

        self.center_panel = tk.Frame(self.faceplate, bg="#1a1a1a")
        self.center_panel.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.knob = tk.Canvas(self.keypad_panel, width=100, height=100, bg="#1a1a1a", highlightthickness=0, cursor="hand2")
        self.knob.pack(pady=(0, 12))
        self.knob.create_oval(5, 5, 95, 95, fill="#222222", outline="#111111")
        self.knob.create_oval(10, 10, 90, 90, fill="#777777", outline="#555555")
        self.knob.create_oval(20, 20, 80, 80, fill="#AAAAAA", outline="")
        self.knob.create_oval(30, 30, 70, 70, fill="#DDDDDD", outline="#888888")
        self.knob.create_text(25, 50, text="◀", fill="#111111", font=(self.sans_family, 14, "bold"))
        self.knob.create_text(75, 50, text="▶", fill="#111111", font=(self.sans_family, 14, "bold"))
        self.knob.create_text(50, 50, text="PUSH\n[E]", fill="#111111", font=(self.sans_family, 8, "bold"), justify="center")

        self.knob.bind("<Button-1>", lambda e: self.send_key("<") if e.x < 35 else (self.send_key(">") if e.x > 65 else self.send_key("E")))
        self.knob.bind("<Button-4>", lambda e: self.send_key("<"))
        self.knob.bind("<Button-5>", lambda e: self.send_key(">"))
        self.knob.bind("<MouseWheel>", lambda e: self.send_key("<") if e.delta > 0 else self.send_key(">"))

        btn_style = {
            "font": (self.sans_family, 10, "bold"), "bg": "#111111", "fg": "#FFFFFF",
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
            row_f.pack(fill=tk.X, pady=2)
            for text, key_code in row:
                tk.Button(
                    row_f, text=text, width=12 if len(row) == 2 else 7, height=1,
                    command=lambda k=key_code: self.send_key(k), **btn_style
                ).pack(side=tk.LEFT, padx=3, expand=True)

        self.lcd_header = tk.Frame(self.center_panel, bg="#1a1a1a")
        self.lcd_header.pack(fill=tk.X, padx=20, pady=(0, 5))

        tk.Label(self.lcd_header, text="UNIDEN BCD536HP", fg="#AAAAAA", bg="#1a1a1a", font=(self.sans_family, 12, "bold")).pack(side=tk.LEFT)
        self.link_label = tk.Label(self.lcd_header, text="[USB: INIT]", fg="#39FF14", bg="#1a1a1a", font=(self.mono_family, 11, "bold"))
        self.link_label.pack(side=tk.LEFT, padx=(10, 0))

        self.status_label = tk.Label(self.lcd_header, text="CONNECTING...", fg="#39FF14", bg="#1a1a1a", font=(self.mono_family, 12, "bold"))
        self.status_label.pack(side=tk.RIGHT)
        self.sig_label = tk.Label(self.lcd_header, text="SIG: \u25a1 \u25a1 \u25a1 \u25a1 \u25a1", fg="#555555", bg="#1a1a1a", font=(self.mono_family, 12, "bold"))
        self.sig_label.pack(side=tk.RIGHT, padx=10)
        self.vu_label = tk.Label(self.lcd_header, text="VU: \u25b1\u25b1\u25b1\u25b1\u25b1", fg="#555555", bg="#1a1a1a", font=(self.mono_family, 12, "bold"))
        self.vu_label.pack(side=tk.RIGHT, padx=8)
        self.cc_indicator = tk.Label(self.lcd_header, text="\u2B24 CC: OFF", fg="#555555", bg="#1a1a1a", font=(self.sans_family, 12, "bold"))
        self.cc_indicator.pack(side=tk.RIGHT, padx=8)

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
        soft_f.pack(fill=tk.X, padx=20, pady=(8, 4))
        for text, key_code in [("SYS", "A"), ("DEPT", "B"), ("CH", "C"), ("AVOID", "L"), ("ZIP", "Z"), ("SERV", "T")]:
            tk.Button(soft_f, text=text, height=2, command=lambda k=key_code: self.send_key(k), **btn_style).pack(side=tk.LEFT, padx=4, expand=True, fill=tk.X)

        self.log_ctrl_frame = tk.Frame(self.software_panel, bg="#050505")
        self.log_ctrl_frame.pack(fill=tk.X, pady=(0, 6))

        qk_frame = tk.Frame(self.log_ctrl_frame, bg="#050505")
        qk_frame.pack(side=tk.LEFT)
        tk.Label(qk_frame, text="QK:", fg="#00FFFF", bg="#050505", font=(self.mono_family, 10, "bold")).pack(side=tk.LEFT, padx=(0, 4))
        self.qk_entry = tk.Entry(qk_frame, width=8, bg="#151515", fg="#39FF14", insertbackground="#39FF14", font=(self.mono_family, 10, "bold"))
        self.qk_entry.pack(side=tk.LEFT, padx=2)
        self.qk_entry.bind("<Return>", lambda e: self.send_quick_key())

        btn_config = {"font": (self.sans_family, 9, "bold"), "bg": "#1a1a1a", "bd": 0, "cursor": "hand2", "padx": 6, "pady": 3}
        tk.Button(qk_frame, text="SEND", fg="#39FF14", command=self.send_quick_key, **btn_config).pack(side=tk.LEFT, padx=3)
        tk.Label(qk_frame, text="FLT:", fg="#FFA500", bg="#050505", font=(self.mono_family, 10, "bold")).pack(side=tk.LEFT, padx=(6, 2))
        self.filter_entry = tk.Entry(qk_frame, width=10, bg="#151515", fg="#FFFFFF", insertbackground="#FFFFFF", font=(self.mono_family, 10))
        self.filter_entry.pack(side=tk.LEFT, padx=2); self.filter_entry.bind("<KeyRelease>", lambda e: self._apply_live_filter())
        self.min2s_btn = tk.Button(qk_frame, text="● MIN2S" if self.skip_short_calls else "○ MIN2S", fg="#39FF14" if self.skip_short_calls else "#888888", command=self.toggle_min2s, **btn_config)
        self.min2s_btn.pack(side=tk.LEFT, padx=2)
        tk.Button(qk_frame, text="■ STOP", fg="#FF5555", command=self.stop_playback, **btn_config).pack(side=tk.LEFT, padx=2)

        for txt, fg_col, cmd in [
            ("CLEAR", "#00FFFF", self.clear_log),
            ("CSV", "#39FF14", self.export_csv),
            ("FOLDER", "#00FFFF", self.open_audio_folder),
            ("RETENTION", "#FFA500", self.set_retention),
        ]:
            tk.Button(self.log_ctrl_frame, text=txt, fg=fg_col, command=cmd, **btn_config).pack(side=tk.RIGHT, padx=2)

        self.web_btn = tk.Button(self.log_ctrl_frame, text="○ WEB", fg="#888888", command=self.toggle_web_server, **btn_config)
        self.web_btn.pack(side=tk.RIGHT, padx=2)

        self.udp_btn = tk.Button(
            self.log_ctrl_frame,
            text="● WIFI CTRL" if self.prefer_udp_control else "● USB CTRL",
            fg="#00FFFF" if self.prefer_udp_control else "#39FF14",
            command=self.toggle_udp_control, **btn_config
        )
        self.udp_btn.pack(side=tk.RIGHT, padx=2)

        self.ip_btn = tk.Button(self.log_ctrl_frame, text="WIFI SETUP", fg="#FFFF00", command=self.set_ip, **btn_config)
        self.ip_btn.pack(side=tk.RIGHT, padx=2)

        self.listen_btn = tk.Button(self.log_ctrl_frame, text="○ LISTEN", fg="#888888", command=self.toggle_wifi_listen, **btn_config)
        self.listen_btn.pack(side=tk.RIGHT, padx=2)

        self.wifi_rec_btn = tk.Button(self.log_ctrl_frame, text="○ WIFI REC", fg="#888888", command=self.toggle_wifi_record, **btn_config)
        self.wifi_rec_btn.pack(side=tk.RIGHT, padx=2)

        self.usb_rec_btn = tk.Button(self.log_ctrl_frame, text="○ USB REC", fg="#888888", command=self.toggle_usb_record, **btn_config)
        self.usb_rec_btn.pack(side=tk.RIGHT, padx=2)

        self.sd_rec_btn = tk.Button(self.log_ctrl_frame, text="SD REC", fg="#FF0000", command=self.toggle_sd_record, **btn_config)
        self.sd_rec_btn.pack(side=tk.RIGHT, padx=2)

        self.color_btn = tk.Button(self.log_ctrl_frame, text="LCD", fg="#FFFFFF", command=self.cycle_lcd_color, **btn_config)
        self.color_btn.pack(side=tk.RIGHT, padx=2)

        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background="#050505", borderwidth=0)
        style.configure("TNotebook.Tab", background="#1a1a1a", foreground="#AAAAAA", padding=[12, 5], font=(self.sans_family, 10, "bold"))
        style.map("TNotebook.Tab", background=[("selected", "#0055FF")], foreground=[("selected", "#FFFFFF")])
        style.configure("Treeview", background="#FFFFFF", foreground="#000000", fieldbackground="#FFFFFF", rowheight=30, font=(self.sans_family, 11, "bold"))
        style.configure("Treeview.Heading", background="#D0D0D0", foreground="#000000", font=(self.sans_family, 10, "bold"), relief="raised")
        style.map("Treeview", background=[("selected", "#0055FF")], foreground=[("selected", "#FFFFFF")])

        self.notebook = ttk.Notebook(self.software_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self.notebook.bind("<<NotebookTabChanged>>", lambda e: self._apply_live_filter())

        self.tab_summary = tk.Frame(self.notebook, bg="#050505")
        self.notebook.add(self.tab_summary, text="  SUMMARY / CHANNEL HITS  ")

        self.tree_columns = ("time", "sys", "dept", "chan", "freq", "tgid", "uid", "hits", "call_time")
        self.log_tree = ttk.Treeview(self.tab_summary, columns=self.tree_columns, show="headings", selectmode="browse")
        for col_id, heading, width, anchor in [
            ("time", "LAST SEEN", 105, "center"), ("sys", "SYSTEM", 165, "w"),
            ("dept", "DEPARTMENT", 165, "w"), ("chan", "CHANNEL", 175, "w"),
            ("freq", "FREQ / MOD", 115, "center"), ("tgid", "TGID", 75, "center"),
            ("uid", "LAST UID / ALIAS", 145, "center"), ("hits", "HITS", 55, "center"),
            ("call_time", "TOTAL TIME", 85, "center"),
        ]:
            self.log_tree.heading(col_id, text=heading)
            self.log_tree.column(col_id, width=width, anchor=anchor)

        self.log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sum_scroll = tk.Scrollbar(self.tab_summary, command=self.log_tree.yview, bg="#1a1a1a")
        sum_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_tree.config(yscrollcommand=sum_scroll.set)
        self.log_tree.bind("<Double-1>", lambda e: self.send_key("C") if self.log_tree.selection() else None)

        self.tab_history = tk.Frame(self.notebook, bg="#050505")
        self.notebook.add(self.tab_history, text="  CHRONOLOGICAL CALL HISTORY & AUDIO  ")

        self.hist_columns = ("timestamp", "sys", "dept", "chan", "freq", "tgid", "uid", "duration", "clip")
        self.hist_tree = ttk.Treeview(self.tab_history, columns=self.hist_columns, show="headings", selectmode="browse")
        for col_id, heading, width, anchor in [
            ("timestamp", "DATE / TIME", 150, "center"), ("sys", "SYSTEM", 155, "w"),
            ("dept", "DEPARTMENT", 155, "w"), ("chan", "CHANNEL", 165, "w"),
            ("freq", "FREQ / MOD", 110, "center"), ("tgid", "TGID", 70, "center"),
            ("uid", "UID / ALIAS", 145, "center"), ("duration", "DURATION", 75, "center"),
            ("clip", "AUDIO CLIP (Double-Click to Play)", 190, "w"),
        ]:
            self.hist_tree.heading(col_id, text=heading)
            self.hist_tree.column(col_id, width=width, anchor=anchor)

        self.hist_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        hist_scroll = tk.Scrollbar(self.tab_history, command=self.hist_tree.yview, bg="#1a1a1a")
        hist_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.hist_tree.config(yscrollcommand=hist_scroll.set)
        self.hist_tree.bind("<Double-1>", self.play_selected_history_clip)

        self.tab_uids = tk.Frame(self.notebook, bg="#050505")
        self.notebook.add(self.tab_uids, text="  UID DATABASE & ALIASES (Double-Click to Tag)  ")

        self.uid_columns = ("uid", "alias", "last_chan", "last_seen", "hits")
        self.uid_tree = ttk.Treeview(self.tab_uids, columns=self.uid_columns, show="headings", selectmode="browse")
        for col_id, heading, width, anchor in [
            ("uid", "RADIO UNIT ID (UID)", 160, "center"), ("alias", "ASSIGNED ALIAS NAME", 260, "w"),
            ("last_chan", "LAST ACTIVE CHANNEL", 280, "w"), ("last_seen", "LAST SEEN", 150, "center"),
            ("hits", "TOTAL HITS", 100, "center"),
        ]:
            self.uid_tree.heading(col_id, text=heading)
            self.uid_tree.column(col_id, width=width, anchor=anchor)

        self.uid_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        uid_scroll = tk.Scrollbar(self.tab_uids, command=self.uid_tree.yview, bg="#1a1a1a")
        uid_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.uid_tree.config(yscrollcommand=uid_scroll.set)
        self.uid_tree.bind("<Double-1>", self.edit_selected_uid_alias)

        for tree in (self.log_tree, self.hist_tree, self.uid_tree):
            linscan_pro.attach_sorting(tree)
            tree.tag_configure("law", background="#E6F0FA", foreground="#000000")
            tree.tag_configure("fire", background="#FAE6E6", foreground="#000000")
            tree.tag_configure("ems", background="#E6FAE6", foreground="#000000")
            tree.tag_configure("works", background="#FAF0E6", foreground="#000000")
            tree.tag_configure("dnr", background="#E6F5EA", foreground="#000000")
            tree.tag_configure("default", background="#FFFFFF", foreground="#000000")

    def _refresh_web_snapshot(self):
        """Update cached web snapshot safely on the Tkinter main thread."""
        hist_rows = []
        for item_id in self.hist_tree.get_children()[:25]:
            vals = self.hist_tree.item(item_id, "values")
            if vals:
                hist_rows.append(list(vals[:8]))
        snapshot = {
            "link": self.link_label.cget("text").strip("[]"),
            "status": self.status_label.cget("text"),
            "sig": self.sig_label.cget("text"),
            "lcd": list(self.last_lcd_snapshot),
            "history": hist_rows,
        }
        with self._web_lock:
            self._web_snapshot = snapshot

    def _get_web_state(self) -> dict[str, Any]:
        """Thread-safe snapshot getter called by LinScanWebServer worker threads."""
        with self._web_lock:
            return dict(self._web_snapshot)

    def send_quick_key(self):
        seq = self.qk_entry.get().strip()
        if not seq:
            return
        for ch in seq:
            if ch in "0123456789.":
                self.serial_manager.send_cmd(f"KEY,{ch},P\r".encode("ascii"))
        self.serial_manager.send_cmd(b"KEY,E,P\r")
        self.qk_entry.delete(0, tk.END)
        self.focus_set()

    def toggle_udp_control(self):
        if not self.prefer_udp_control and not self.scanner_ip:
            self.set_ip()
            if not self.scanner_ip:
                return
        self.prefer_udp_control = not self.prefer_udp_control
        self.udp_btn.config(
            text="● WIFI CTRL" if self.prefer_udp_control else "● USB CTRL",
            fg="#00FFFF" if self.prefer_udp_control else "#39FF14"
        )
        self.save_config()
        self.serial_manager.configure_transport(self.scanner_ip, self.prefer_udp_control)

    def toggle_web_server(self):
        self.web_enabled = not self.web_enabled
        if self.web_enabled:
            self._refresh_web_snapshot()
            if self.web_server.start():
                self.web_btn.config(text=f"● WEB:{self.web_port}", fg="#39FF14")
            else:
                self.web_enabled = False
                messagebox.showerror("Web Server Error", f"Could not bind HTTP port {self.web_port}.")
        else:
            self.web_server.stop()
            self.web_btn.config(text="○ WEB", fg="#888888")

    def play_selected_history_clip(self, event=None):
        sel = self.hist_tree.selection()
        if not sel:
            return
        item_id = sel[0]
        clip_path_str = self.history_clips.get(item_id, "")
        if not clip_path_str or not Path(clip_path_str).exists():
            return
        if self.playback_proc and self.playback_proc.poll() is None:
            try:
                self.playback_proc.terminate()
            except Exception:
                pass
        if self.has_ffplay:
            self.playback_proc = subprocess.Popen(
                ["ffplay", "-nodisp", "-autoexit", "-loglevel", "quiet", clip_path_str],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            subprocess.Popen(["xdg-open", clip_path_str])

    def edit_selected_uid_alias(self, event=None):
        sel = self.uid_tree.selection()
        if not sel:
            return
        uid_key = sel[0]
        current_alias = self.uid_aliases.get(uid_key, "")
        new_alias = simpledialog.askstring(
            "Assign Radio Unit ID Alias",
            f"Enter human-readable name for UID {uid_key}:",
            initialvalue=current_alias,
            parent=self
        )
        if new_alias is None:
            return
        new_alias = new_alias.strip()
        if new_alias:
            self.uid_aliases[uid_key] = new_alias
        else:
            self.uid_aliases.pop(uid_key, None)
        self.save_config()

        old_vals = list(self.uid_tree.item(uid_key, "values"))
        if len(old_vals) >= 2:
            old_vals[1] = new_alias
            self.uid_tree.item(uid_key, values=old_vals)
        linscan_pro.sync_uid_trees(self, uid_key)

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
        widget_class = event.widget.winfo_class() if event.widget else ""
        if widget_class in ("Entry", "TEntry", "Spinbox", "TSpinbox", "Text"):
            return

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
        elif key and key in "0123456789.":
            self.send_key(key)

    def prune_audio_storage(self, target_dir: Path | None = None) -> int:
        base = target_dir or self.audio_dir
        if not base.exists():
            return 0
        removed = 0
        now = time.time()
        max_age_sec = self.retention_days * 86400 if self.retention_days > 0 else 0

        mp3_files = []
        for f in base.rglob("*.mp3"):
            try:
                st = f.stat()
                if max_age_sec > 0 and (now - st.st_mtime) > max_age_sec:
                    f.unlink()
                    removed += 1
                else:
                    mp3_files.append((st.st_mtime, st.st_size, f))
            except OSError:
                pass

        if self.max_audio_mb > 0:
            max_bytes = self.max_audio_mb * 1024 * 1024
            total_bytes = sum(item[1] for item in mp3_files)
            if total_bytes > max_bytes:
                mp3_files.sort(key=lambda x: x[0])
                for _, sz, f in mp3_files:
                    if total_bytes <= max_bytes:
                        break
                    try:
                        f.unlink()
                        total_bytes -= sz
                        removed += 1
                    except OSError:
                        pass
        return removed

    def set_retention(self):
        top = tk.Toplevel(self)
        top.title("Audio Retention Policy")
        top.geometry("360x210")
        top.configure(bg="#1a1a1a")
        top.resizable(False, False)
        top.transient(self)

        tk.Label(top, text="Max Age in Days (0 = Unlimited):", fg="#FFFFFF", bg="#1a1a1a", font=(self.sans_family, 10, "bold")).pack(pady=(12, 2))
        days_ent = tk.Entry(top, font=(self.sans_family, 11), justify="center")
        days_ent.insert(0, str(self.retention_days))
        days_ent.pack(padx=40, fill=tk.X)

        tk.Label(top, text="Max Folder Size in MB (0 = Unlimited):", fg="#FFFFFF", bg="#1a1a1a", font=(self.sans_family, 10, "bold")).pack(pady=(10, 2))
        mb_ent = tk.Entry(top, font=(self.sans_family, 11), justify="center")
        mb_ent.insert(0, str(self.max_audio_mb))
        mb_ent.pack(padx=40, fill=tk.X)

        def save_ret():
            try:
                self.retention_days = max(0, int(days_ent.get().strip()))
                self.max_audio_mb = max(0, int(mb_ent.get().strip()))
                self.save_config()
                self.prune_audio_storage()
            except ValueError:
                pass
            top.destroy()

        btn_f = tk.Frame(top, bg="#1a1a1a")
        btn_f.pack(pady=14)
        tk.Button(btn_f, text="Save & Prune", width=12, bg="#333333", fg="#39FF14", font=(self.sans_family, 9, "bold"), command=save_ret).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_f, text="Cancel", width=10, bg="#333333", fg="#FFFFFF", font=(self.sans_family, 9, "bold"), command=top.destroy).pack(side=tk.LEFT, padx=5)

    def open_audio_folder(self):
        self.audio_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.Popen(["xdg-open", str(self.audio_dir)])
        except OSError as err:
            logging.error("Failed to open audio folder: %s", err)

    def export_csv(self):
        active_tab = self.notebook.index(self.notebook.select())
        tree = self.hist_tree if active_tab == 1 else (self.uid_tree if active_tab == 2 else self.log_tree)
        items = tree.get_children()
        if not items:
            return
        default_name = f"LinScan_Export_{datetime.datetime.now().strftime('%Y-%m-%d_%I-%M-%S%p')}.csv"
        out_path = filedialog.asksaveasfilename(
            defaultextension=".csv", initialfile=default_name, filetypes=[("CSV Files", "*.csv")]
        )
        if out_path:
            try:
                with open(out_path, "w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    headers = [tree.heading(col)["text"] for col in tree["columns"]]
                    writer.writerow(headers)
                    for item in items:
                        writer.writerow(tree.item(item)["values"])
            except OSError as err:
                logging.error("CSV export failed: %s", err)

    def set_ip(self):
        """Wi-Fi Setup dialog with IPv4 validation and live ProScan-style UDP/RTSP test."""
        top = tk.Toplevel(self)
        top.title("BCD536HP Wi-Fi Setup & Diagnostics")
        top.geometry("430x255")
        top.configure(bg="#1a1a1a")
        top.resizable(False, False)
        top.transient(self)

        tk.Label(
            top,
            text="Scanner Wi-Fi IPv4 Address\n(Scanner: MENU → Wi-Fi Setup → Show Wi-Fi Information)",
            fg="#FFFFFF", bg="#1a1a1a", font=(self.sans_family, 10, "bold")
        ).pack(pady=(12, 6))

        entry = tk.Entry(top, font=(self.mono_family, 12, "bold"), justify="center", bg="#111111", fg="#39FF14", insertbackground="#39FF14")
        entry.insert(0, self.scanner_ip)
        entry.pack(pady=4, padx=35, fill=tk.X)
        entry.focus_set()

        udp_res_lbl = tk.Label(top, text="UDP 50536 Control: Not tested", fg="#AAAAAA", bg="#1a1a1a", font=(self.sans_family, 9, "bold"))
        udp_res_lbl.pack(pady=(8, 2))
        rtsp_res_lbl = tk.Label(top, text="TCP 554 RTSP Audio: Not tested", fg="#AAAAAA", bg="#1a1a1a", font=(self.sans_family, 9, "bold"))
        rtsp_res_lbl.pack(pady=(0, 8))

        def run_test():
            candidate = validate_scanner_ip(entry.get())
            if not candidate:
                messagebox.showerror("Invalid IP", "Please enter a valid IPv4 address (e.g., 192.168.68.50).", parent=top)
                return
            udp_res_lbl.config(text="UDP 50536 Control: Testing...", fg="#FFFF00")
            rtsp_res_lbl.config(text="TCP 554 RTSP Audio: Testing...", fg="#FFFF00")

            def _worker():
                res = test_wifi_scanner(candidate)
                def _show():
                    if not top.winfo_exists():
                        return
                    udp_res_lbl.config(
                        text=f"UDP 50536 Control: {res['udp_msg']}",
                        fg="#39FF14" if res["udp_ok"] else "#FF5555",
                    )
                    rtsp_res_lbl.config(
                        text=f"TCP 554 RTSP Audio: {res['rtsp_msg']}",
                        fg="#39FF14" if res["rtsp_ok"] else "#FF5555",
                    )
                self.after(0, _show)

            threading.Thread(target=_worker, daemon=True).start()

        def save_and_close():
            raw = entry.get().strip()
            if not raw:
                self.scanner_ip = ""
                self.save_config()
                top.destroy()
                return
            valid = validate_scanner_ip(raw)
            if not valid:
                messagebox.showerror("Invalid IP", "Please enter a valid IPv4 address (e.g., 192.168.68.50).", parent=top)
                return
            self.scanner_ip = valid
            self.save_config()
            if self.prefer_udp_control:
                self.serial_manager.configure_transport(self.scanner_ip, self.prefer_udp_control)
            top.destroy()

        btn_f = tk.Frame(top, bg="#1a1a1a")
        btn_f.pack(pady=10)
        tk.Button(btn_f, text="Test Wi-Fi", width=11, bg="#333333", fg="#00FFFF", font=(self.sans_family, 9, "bold"), command=run_test).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_f, text="Save", width=10, bg="#333333", fg="#39FF14", font=(self.sans_family, 9, "bold"), command=save_and_close).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_f, text="Cancel", width=10, bg="#333333", fg="#FFFFFF", font=(self.sans_family, 9, "bold"), command=top.destroy).pack(side=tk.LEFT, padx=5)
        top.bind("<Return>", lambda e: save_and_close())

    def toggle_sd_record(self):
        self.serial_manager.send_cmd(b"KEY,F,P\r")
        self.after(300, lambda: self.serial_manager.send_cmd(b"KEY,Y,P\r"))

    def toggle_usb_record(self):
        if not self.has_ffmpeg:
            messagebox.showerror("Missing Dependency", "FFmpeg is not installed. Please install ffmpeg via apt.")
            return
        self.usb_record_enabled = not self.usb_record_enabled
        if self.usb_record_enabled:
            self.usb_rec_btn.config(text="● USB REC", fg="#FF0000")
            self.audio_dir.mkdir(parents=True, exist_ok=True)
            mp3_path = self.audio_dir / f"Session_USB_{datetime.datetime.now().strftime('%Y-%m-%d_%I-%M-%S%p')}.mp3"
            self.usb_engine = USBRecordingEngine(mp3_path)
            self.usb_engine.start()
        else:
            self.usb_rec_btn.config(text="○ USB REC", fg="#888888")
            if self.usb_engine:
                eng = self.usb_engine
                self.usb_engine = None
                threading.Thread(target=eng.stop, daemon=True).start()

    def _on_rtsp_status(self, state: str):
        self._rtsp_status_text = state

    def _ensure_rtsp_engine_state(self):
        """Start, update, or cleanly stop the shared RTSP Wi-Fi audio engine."""
        want_any = self.record_enabled or self.live_listen_enabled
        if want_any:
            vox_path = None
            if self.record_enabled:
                self.audio_dir.mkdir(parents=True, exist_ok=True)
                self.clips_dir.mkdir(parents=True, exist_ok=True)
                vox_path = self.audio_dir / f"Session_VOX_{datetime.datetime.now().strftime('%Y-%m-%d_%I-%M-%S%p')}.mp3"

            if self.rtsp_engine is None or not self.rtsp_engine.is_alive():
                self.rtsp_engine = RTSPAudioEngine(
                    self.scanner_ip,
                    session_mp3_path=vox_path,
                    live_monitor=self.live_listen_enabled,
                    preferred_rtp_port=self.rtp_client_port,
                    status_callback=self._on_rtsp_status,
                )
                self.rtsp_engine.start()
            else:
                self.rtsp_engine.set_live_monitor(self.live_listen_enabled)
                if self.record_enabled and vox_path:
                    self.rtsp_engine.start_session_recording(vox_path)
                elif not self.record_enabled:
                    self.rtsp_engine.stop_session_recording()
        else:
            if self.rtsp_engine:
                eng = self.rtsp_engine
                self.rtsp_engine = None
                self._rtsp_status_text = "OFF"
                threading.Thread(target=eng.stop, daemon=True).start()

    def toggle_wifi_listen(self):
        if not self.has_ffplay:
            messagebox.showerror("Missing Dependency", "ffplay (part of ffmpeg) is not installed. Install ffmpeg via apt.")
            return
        if not self.scanner_ip:
            self.set_ip()
            if not self.scanner_ip:
                return
        self.live_listen_enabled = not self.live_listen_enabled
        self.listen_btn.config(
            text="● LISTEN" if self.live_listen_enabled else "○ LISTEN",
            fg="#39FF14" if self.live_listen_enabled else "#888888",
        )
        self._ensure_rtsp_engine_state()

    def toggle_wifi_record(self):
        if not self.has_ffmpeg:
            messagebox.showerror("Missing Dependency", "FFmpeg is not installed. Please install ffmpeg via apt.")
            return
        if not self.scanner_ip:
            self.set_ip()
            if not self.scanner_ip:
                return
        self.record_enabled = not self.record_enabled
        self.wifi_rec_btn.config(
            text="● WIFI REC" if self.record_enabled else "○ WIFI REC",
            fg="#FF0000" if self.record_enabled else "#888888",
        )
        self._ensure_rtsp_engine_state()

    def commit_log(self):
        sys_final = clean_text_for_log(self.log_sys.full_text).strip()
        dept_final = clean_text_for_log(self.log_dept.full_text).strip()
        chan_final = clean_text_for_log(self.log_chan.full_text).strip()
        uid_final = self.current_uid.strip()
        tgid_final = self.current_tgid.strip()
        freq_final = self.current_freq.strip()
        mod_final = self.current_mod.strip()
        call_start = self.current_call_start

        saved_clip: Path | None = None
        if self.rtsp_engine and self.record_enabled:
            saved_clip = self.rtsp_engine.finalize_call_clip()

        self.active_call = False
        self.current_uid = ""
        self.current_tgid = ""
        self.current_freq = ""
        self.current_mod = ""
        self.current_clip_path = None
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

        elapsed = max(0.0, time.time() - call_start) if call_start is not None else 0.0
        if self.skip_short_calls and elapsed < 2.0:
            if saved_clip and saved_clip.exists():
                try: saved_clip.unlink()
                except OSError: pass
            return
        self.call_times[tg_key] = self.call_times.get(tg_key, 0.0) + elapsed
        self.tg_hits[tg_key] = self.tg_hits.get(tg_key, 0) + 1

        total_sec = int(self.call_times.get(tg_key, 0))
        mins, secs = divmod(total_sec, 60)
        hours, mins = divmod(mins, 60)
        time_str = f"{hours:02d}:{mins:02d}:{secs:02d}" if hours > 0 else f"{mins:02d}:{secs:02d}"

        call_dur_sec = max(1, int(round(elapsed)))
        c_mins, c_secs = divmod(call_dur_sec, 60)
        call_dur_str = f"{c_mins:02d}:{c_secs:02d}"

        now_dt = datetime.datetime.now()
        now_str = now_dt.strftime("%I:%M:%S %p")
        full_ts_str = now_dt.strftime("%Y-%m-%d %I:%M:%S %p")
        freq_mod_display = f"{freq_final} {mod_final}".strip() if freq_final else mod_final

        clip_label = ""
        if saved_clip and saved_clip.exists():
            meta_name = (
                f"{now_dt.strftime('%Y%m%d_%H%M%S')}_"
                f"{sanitize_filename_token(dept_final, 'DEPT')}_"
                f"{sanitize_filename_token(chan_final, 'CHAN')}_"
                f"{sanitize_filename_token(tgid_final, 'CONV')}.mp3"
            )
            final_clip_path = saved_clip.parent / meta_name
            try:
                saved_clip.rename(final_clip_path)
                saved_clip = final_clip_path
                threading.Thread(target=self.prune_audio_storage, daemon=True).start()
            except OSError:
                pass
            clip_label = f"▶ {saved_clip.name}"

        uid_display = self.format_uid_display(uid_final)

        if self.log_tree.exists(tg_key):
            old_vals = self.log_tree.item(tg_key, "values")
            if not uid_display and len(old_vals) > 6 and old_vals[6]:
                uid_display = old_vals[6]
            if not tgid_final and len(old_vals) > 5 and old_vals[5]:
                tgid_final = old_vals[5]
            if not freq_mod_display and len(old_vals) > 4 and old_vals[4]:
                freq_mod_display = old_vals[4]

        row_vals = (
            now_str, sys_final, dept_final, chan_final,
            freq_mod_display, tgid_final, uid_display,
            self.tg_hits[tg_key], time_str
        )
        row_tag = classify_agency_tag(dept_final, chan_final)

        try:
            if self.log_tree.exists(tg_key):
                self.log_tree.item(tg_key, values=row_vals, tags=(row_tag,))
                self.log_tree.move(tg_key, "", 0)
            else:
                self.log_tree.insert("", 0, iid=tg_key, values=row_vals, tags=(row_tag,))
                children = self.log_tree.get_children()
                if len(children) > MAX_LOG_ROWS:
                    oldest_key = children[-1]
                    self.log_tree.delete(oldest_key)
                    self.tg_hits.pop(oldest_key, None)
                    self.call_times.pop(oldest_key, None)

            hist_id = f"H_{time.time_ns()}"
            hist_vals = (
                full_ts_str, sys_final, dept_final, chan_final,
                freq_mod_display, tgid_final, self.format_uid_display(uid_final),
                call_dur_str, clip_label
            )
            self.hist_tree.insert("", 0, iid=hist_id, values=hist_vals, tags=(row_tag,))
            if saved_clip:
                self.history_clips[hist_id] = str(saved_clip)
            hist_children = self.hist_tree.get_children()
            if len(hist_children) > MAX_HISTORY_ROWS:
                old_h = hist_children[-1]
                self.hist_tree.delete(old_h)
                self.history_clips.pop(old_h, None)

            if uid_final:
                self.uid_hits[uid_final] = self.uid_hits.get(uid_final, 0) + 1
                uid_vals = (
                    uid_final,
                    self.uid_aliases.get(uid_final, ""),
                    f"{dept_final} - {chan_final}".strip(" -"),
                    now_str,
                    self.uid_hits[uid_final],
                )
                if self.uid_tree.exists(uid_final):
                    self.uid_tree.item(uid_final, values=uid_vals, tags=(row_tag,))
                    self.uid_tree.move(uid_final, "", 0)
                else:
                    self.uid_tree.insert("", 0, iid=uid_final, values=uid_vals, tags=(row_tag,))
            self.call_store.add_call((full_ts_str, now_str, sys_final, dept_final, chan_final, freq_mod_display, tgid_final, uid_final, elapsed, str(saved_clip) if saved_clip else "", row_tag))
        except Exception as e:
            logging.warning("Error writing row to activity log: %s", e)

    def on_closing(self):
        self.save_config()
        self.call_store.close()
        self.record_enabled = False
        self.live_listen_enabled = False
        self.usb_record_enabled = False
        self.web_server.stop()
        if self.rtsp_engine:
            self.rtsp_engine.stop()
        if self.usb_engine:
            self.usb_engine.stop_async()
        if self.serial_manager:
            self.serial_manager.stop()
        if self.playback_proc and self.playback_proc.poll() is None:
            try:
                self.playback_proc.terminate()
            except Exception:
                pass
        self.destroy()

    def clear_log(self):
        for tree in (self.log_tree, self.hist_tree):
            for item in tree.get_children():
                tree.delete(item)
        self.tg_hits.clear()
        self.call_times.clear()
        self.history_clips.clear(); self._hidden.clear(); self.call_store.clear()

    def toggle_min2s(self):
        self.skip_short_calls = not self.skip_short_calls
        self.min2s_btn.config(text='● MIN2S' if self.skip_short_calls else '○ MIN2S', fg='#39FF14' if self.skip_short_calls else '#888888')
        self.save_config()
    def stop_playback(self):
        if self.playback_proc and self.playback_proc.poll() is None:
            try: self.playback_proc.terminate()
            except Exception: pass
    def _apply_live_filter(self):
        q = self.filter_entry.get()
        t = (self.log_tree, self.hist_tree, self.uid_tree)[self.notebook.index(self.notebook.select())]
        linscan_pro.apply_filter(t, self._hidden, q)
    def send_key(self, key_code: str):
        self.serial_manager.send_cmd(f"KEY,{key_code},P\r".encode("ascii"))

    def send_volume(self):
        self.vol_dragging = False
        self.last_vol_change = time.time()
        val = int(self.vol_slider.get())
        self.serial_manager.send_cmd(f"VOL,{val:02d}\r".encode("ascii"))

    def send_squelch(self):
        self.sql_dragging = False
        self.last_sql_change = time.time()
        val = int(self.sql_slider.get())
        self.serial_manager.send_cmd(f"SQL,{val:02d}\r".encode("ascii"))

    def process_serial_queue(self):
        latest_sts = None
        latest_gsi = None
        now = time.time()

        while not self.serial_queue.empty():
            try:
                item = self.serial_queue.get_nowait()
                msg_type = item[0]

                if msg_type == "LINK":
                    badge_txt, badge_col = item[1][0], item[1][1]
                    self.link_label.config(text=f"[{badge_txt}]", fg=badge_col)
                elif msg_type == "STATUS":
                    text, color = item[1][0], item[1][1]
                    self.status_label.config(text=text, fg=color)
                    self._last_scan_state = None
                elif msg_type == "RAW":
                    line = item[1]
                    if line.startswith("STS,"):
                        latest_sts = line
                    elif line.startswith("GSI,") or "<ScannerInfo" in line:
                        latest_gsi = line
                    elif line.startswith("VOL,"):
                        if not self.vol_dragging and (now - self.last_vol_change > 1.0):
                            try:
                                self.vol_slider.set(int(line.split(",")[1]))
                            except Exception:
                                pass
                    elif line.startswith("SQL,"):
                        if not self.sql_dragging and (now - self.last_sql_change > 1.0):
                            try:
                                self.sql_slider.set(int(line.split(",")[1]))
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

        if latest_gsi:
            parsed = parse_gsi_xml(latest_gsi)
            if parsed:
                self.latest_gsi = parsed
                if self.active_call:
                    if parsed.system:
                        self.log_sys.update(parsed.system)
                    if parsed.department:
                        self.log_dept.update(parsed.department)
                    if parsed.channel:
                        self.log_chan.update(parsed.channel)
                    if parsed.uid:
                        self.current_uid = parsed.uid
                    if parsed.tgid:
                        self.current_tgid = parsed.tgid
                    if parsed.frequency:
                        self.current_freq = parsed.frequency
                    if parsed.modulation:
                        self.current_mod = parsed.modulation

        if latest_sts:
            self.update_display(latest_sts)

        if self.rtsp_engine and (self.record_enabled or self.live_listen_enabled):
            if self._rtsp_status_text in ("RECONNECTING", "STREAM BUSY", "CONNECTING"):
                self.vu_label.config(text=f"AUD: {self._rtsp_status_text}", fg="#FFA500")
            else:
                vu = self.rtsp_engine.current_vu_level if (now - self.rtsp_engine.last_vu_time < 0.35) else 0
                vu_txt = f"VU: {'▰' * vu}{'▱' * (5 - vu)}"
                vu_col = ["#555555", "#39FF14", "#39FF14", "#FFFF00", "#FFA500", "#FF0000"][vu]
                self.vu_label.config(text=vu_txt, fg=vu_col)
        else:
            self.vu_label.config(text="VU: ▱▱▱▱▱", fg="#555555")

        if self.web_enabled and (now - self._last_web_sync >= 0.4):
            self._last_web_sync = now; self._refresh_web_snapshot()
        self.after(40, self.process_serial_queue)

    def is_numeric_or_empty(self, s: str) -> bool:
        return s == "" or s.isdigit()

    def _begin_active_call(self):
        self.active_call = True
        self.current_call_start = time.time()
        self.log_sys = ScrollCatcher()
        self.log_dept = ScrollCatcher()
        self.log_chan = ScrollCatcher()
        if self.rtsp_engine and self.record_enabled:
            self.clips_dir.mkdir(parents=True, exist_ok=True)
            tmp_clip = self.clips_dir / f"clip_{int(self.current_call_start * 1000)}.mp3"
            self.current_clip_path = tmp_clip
            self.rtsp_engine.start_call_clip(tmp_clip)

    def update_display(self, line: str):
        try:
            line = line.strip("\r\n\x00")
            if not line.startswith("STS,"):
                return
            line = line[4:]

            uid_raw = ""
            tgid_name = ""
            freq_raw = ""

            fields = [x.strip() for x in line.split(",")]
            hw_idx = -1
            for i in range(len(fields) - 5, max(-1, len(fields) - 16), -1):
                if (
                    fields[i].strip() in ["0", "1"]
                    and fields[i + 1].strip() in ["0", "1"]
                    and self.is_numeric_or_empty(fields[i + 2].strip())
                    and self.is_numeric_or_empty(fields[i + 3].strip())
                    and self.is_numeric_or_empty(fields[i + 4].strip())
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
                    if next_fmt in ("", "1") or bool(FMT_REGEX.fullmatch(next_fmt)):
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
                    self.last_lcd_snapshot[i] = display_lines[i]
                else:
                    self.lcd_canvas.itemconfig(self.lcd_texts[i], text="")
                    self.last_lcd_snapshot[i] = ""

            for t_line in raw_lines:
                u_match = UID_REGEX.search(t_line)
                if u_match:
                    cand = u_match.group(1).strip()
                    if cand and not is_status_line(cand):
                        uid_raw = cand
                t_match = TGID_REGEX.search(t_line)
                if t_match:
                    t_cand = t_match.group(1).strip()
                    t_nums = NUM_REGEX.findall(t_cand)
                    tgid_name = t_nums[-1] if t_nums else t_cand
                f_match = FREQ_REGEX.search(t_line)
                if f_match:
                    freq_raw = f"{f_match.group(1)} MHz"

            full_text_upper = "\n".join(display_lines).upper()

            if "CC DND" in full_text_upper:
                self.cc_indicator.config(text="\u2B24 CC: DND", fg="#FFFF00")
            elif "CC PRI" in full_text_upper:
                self.cc_indicator.config(text="\u2B24 CC: PRI", fg="#FF0000")
            elif "CC OFF" in full_text_upper:
                self.cc_indicator.config(text="\u2B24 CC: OFF", fg="#555555")

            if any(kw in full_text_upper for kw in ("MENU", "SETTINGS", "SELECTION")):
                self.status_label.config(text="--- MENU ---", fg="#00FFFF")
                self._last_scan_state = "MENU"
                if self.active_call:
                    self.commit_log()
            else:
                l2 = clean_text_for_log(raw_lines[1]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 1 else ""
                l3 = clean_text_for_log(raw_lines[2]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 2 else ""
                l4 = clean_text_for_log(raw_lines[3]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 3 else ""
                l5 = clean_text_for_log(raw_lines[4]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 4 else ""
                l6 = clean_text_for_log(raw_lines[5]).replace(">", "").replace("▶", "").strip() if len(raw_lines) > 5 else ""

                u5, u6 = l5.upper(), l6.upper()
                is_trunked_search = any(u5.startswith(p) for p in ("ID SEARCH", "ID SCAN", "LINK", "FIND"))
                is_l6_uid = u6.startswith(("UID:", "UID "))
                is_l5_uid = u5.startswith(("UID:", "UID "))

                is_call_active = False
                call_sys, call_dept, call_chan = "", "", ""

                if is_trunked_search:
                    if l6 and not is_status_line(l6):
                        is_call_active = True
                        call_sys, call_dept, call_chan = l3, l4, l6
                elif is_l6_uid:
                    if l5 and not is_status_line(l5):
                        is_call_active = True
                        call_sys, call_dept, call_chan = l3, l4, l5
                elif is_l5_uid:
                    if l4 and not is_status_line(l4):
                        is_call_active = True
                        call_sys, call_dept, call_chan = l2 or l3, l3, l4
                else:
                    if l5 and not is_status_line(l5):
                        is_call_active = True
                        call_sys, call_dept, call_chan = l3, l4, l5
                    elif l6 and not is_status_line(l6):
                        is_call_active = True
                        call_sys, call_dept, call_chan = l3, l4, l6

                if is_call_active:
                    if not self.active_call:
                        self._begin_active_call()
                    self.log_sys.update(call_sys)
                    self.log_dept.update(call_dept)
                    self.log_chan.update(call_chan)
                    if uid_raw:
                        self.current_uid = uid_raw
                    if tgid_name:
                        self.current_tgid = tgid_name
                    if freq_raw:
                        self.current_freq = freq_raw

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
                self._last_sig = sig_text
                self._last_sig_color = current_sig_color
        except Exception as e:
            logging.debug("STS parse error: %s", e)


if __name__ == "__main__":
    app = VirtualScanner()
    app.mainloop()
