#!/bin/bash
# Quick launcher — activates venv and runs the scanner

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VENV="$SCRIPT_DIR/.venv"

if [ ! -d "$VENV" ]; then
    echo "[!] Virtual environment not found. Run install.sh first:"
    echo "    bash install.sh"
    exit 1
fi

source "$VENV/bin/activate"
python3 "$SCRIPT_DIR/scanner.py" "$@"
