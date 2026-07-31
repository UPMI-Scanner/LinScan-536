#!/usr/bin/env bash
sudo apt update && sudo apt install -y python3 python3-pip python3-tk ffmpeg xdg-utils
pip3 install pyserial --break-system-packages
echo 'KERNEL=="ttyACM*|ttyUSB*", MODE="0666"' | sudo tee /etc/udev/rules.d/99-uniden-scanner.rules
sudo udevadm control --reload-rules && sudo udevadm trigger
cp linscan_536.py $HOME/ && chmod +x $HOME/linscan_536.py
mkdir -p $HOME/LinScan_Audio $HOME/.local/share/applications
