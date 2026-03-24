#!/bin/bash
# Quick launcher — uses bundled libs or venv, no install needed

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
VENV="$SCRIPT_DIR/.venv"

if [ -d "$LIB_DIR" ]; then
    # Offline mode: use bundled packages
    export PYTHONPATH="$LIB_DIR:$PYTHONPATH"
    python3 "$SCRIPT_DIR/scanner.py" "$@"
elif [ -d "$VENV" ]; then
    # Venv mode
    source "$VENV/bin/activate"
    python3 "$SCRIPT_DIR/scanner.py" "$@"
else
    echo "[!] No lib/ directory or .venv found."
    echo "    Either use the bundled version or run: bash install.sh"
    exit 1
fi
