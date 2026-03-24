#!/bin/bash
# WebRecon launcher — auto-detects environment and dependencies

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
VENV="$SCRIPT_DIR/.venv"

# Test if lib/ works with current Python
_lib_works() {
    python3 -c "import sys; sys.path.insert(0, '$LIB_DIR'); import aiohttp, requests, rich" 2>/dev/null
}

# Try to install deps via pip (Kali/Debian with root)
_pip_install() {
    if command -v pip3 &>/dev/null; then
        echo "[*] Installing dependencies via pip..."
        pip3 install -r "$SCRIPT_DIR/requirements.txt" --break-system-packages -q 2>/dev/null \
            || pip3 install -r "$SCRIPT_DIR/requirements.txt" -q 2>/dev/null
        return $?
    fi
    return 1
}

# Try venv
_venv_run() {
    if [ ! -d "$VENV" ]; then
        echo "[*] Creating virtual environment..."
        python3 -m venv "$VENV" || return 1
    fi
    source "$VENV/bin/activate"
    pip install -r "$SCRIPT_DIR/requirements.txt" -q 2>/dev/null
}

if _lib_works; then
    # Bundled offline packages work
    export PYTHONPATH="$LIB_DIR:$PYTHONPATH"
    exec python3 "$SCRIPT_DIR/scanner.py" "$@"

elif python3 -c "import aiohttp, requests, rich" 2>/dev/null; then
    # Already installed system-wide
    exec python3 "$SCRIPT_DIR/scanner.py" "$@"

elif _pip_install && python3 -c "import aiohttp, requests, rich" 2>/dev/null; then
    # Installed via pip
    exec python3 "$SCRIPT_DIR/scanner.py" "$@"

elif _venv_run; then
    # Venv fallback
    exec python3 "$SCRIPT_DIR/scanner.py" "$@"

else
    echo "[!] Could not install dependencies. Try manually:"
    echo "    pip3 install aiohttp requests rich"
    exit 1
fi
