# LinScan-536
<img width="1603" height="847" alt="Screenshot_2026-07-31_19-35-12" src="https://github.com/user-attachments/assets/4b164261-4375-4808-95c8-5b62a4b1a78c" />

A high-performance, lightweight Linux virtual control dashboard and RTSP audio recording suite for the **Uniden BCD536HP** radio scanner.

![Platform](https://img.shields.io/badge/Platform-Linux-orange.svg)
![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

---

## Key Features

- **Real-Time LCD Display:** Renders exact front-panel scanner text and signal strength meter over USB serial.
- **Hardware Volume & Squelch Sync:** Queries and automatically mirrors physical volume and squelch knob levels directly on application launch.
- **Virtual Control Panel:** Full virtual front plate with interactive knob controls, keypad shortcuts, and quick channel option keys.
- **Physical Keyboard Hotkeys:** Control your scanner directly using standard PC keyboard binds (Numpad 0-9, Space for Channel Hold, Esc for Avoid, etc.).
- **Deduplicated Activity Table:** Live high-contrast table displaying active talkgroups, timestamps, raw unit IDs (UID), and hit counts.
- **Double-Click Channel Hold:** Double-click any row in the activity table to instantly hold the scanner on that active channel.
- **Wi-Fi RTSP Audio Recording:** Native RTSP Wi-Fi audio stream recording with integrated FFmpeg silence removal, noise spike auto-purging, and timestamped file output.
- **CSV Session Export:** Export live monitoring activity logs to standard .csv spreadsheets with one click.
- **Universal Linux Support:** Includes automatic udev hardware permission rules so any user on the system can connect without permission errors.

---

## Installation

To install LinScan-536 on Debian, Ubuntu, BunsenLabs, or any Debian-based Linux distribution:

git clone https://github.com/UPMI-Scanner/LinScan-536.git

cd LinScan-536

./install.sh

---

## Hardware Connection Guide

1. Connect your **Uniden BCD536HP** scanner to your computer using a USB programming cable.
2. Turn on the scanner. When prompted on the scanner's display, press **. / NO** to select **Serial Port** mode.
3. Open **LinScan-536** from your application menu.

---

## License

Distributed under the MIT License. Free to use, modify, and share.# LinScan-536
Lightweight Linux virtual control dashboard and audio recording suite for the Uniden BCD536HP.
