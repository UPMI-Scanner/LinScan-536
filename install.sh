#!/usr/bin/env bash
set -e
sudo apt update && sudo apt install -y python3 python3-tk python3-serial ffmpeg xdg-utils
echo 'KERNEL=="ttyACM*|ttyUSB*", MODE="0666"' | sudo tee /etc/udev/rules.d/99-uniden-scanner.rules >/dev/null
sudo udevadm control --reload-rules && sudo udevadm trigger
cp linscan_536.py linscan_pro.py "$HOME/" && chmod +x "$HOME/linscan_536.py"
mkdir -p "$HOME/LinScan_Audio" "$HOME/.local/share/applications"
