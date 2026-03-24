#!/bin/bash
set -e

echo "[*] Updating packages..."
sudo apt update -y

echo "[*] Installing Python and venv..."
sudo apt install -y python3 python3-pip python3-venv

echo "[*] Creating virtual environment..."
python3 -m venv .venv
source .venv/bin/activate

echo "[*] Installing Python dependencies..."
pip install -r requirements.txt

echo ""
echo "[+] Installation complete!"
echo "[*] Usage:"
echo "    source .venv/bin/activate"
echo "    python3 scanner.py https://example.com"
echo ""
echo "[*] Or use the shortcut:"
echo "    ./run.sh https://example.com"
