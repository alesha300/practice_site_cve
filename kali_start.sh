#!/bin/bash
# WebRecon — full auto setup and scan for Kali Linux via Whonix Gateway

set -e
REPO="https://github.com/alesha300/practice_site_cve"
DIR="$HOME/webrecon"
GATEWAY="10.152.152.10"
MY_IP="10.152.152.20"

echo "================================================"
echo "  WebRecon — Auto Setup for Kali via Whonix"
echo "================================================"

# ── 1. Network via Whonix Gateway ───────────────────
echo ""
echo "[1/4] Configuring network through Whonix Gateway..."

IFACE=$(ip link show | grep -E "^[0-9]+: (eth|ens|enp|eno)" | head -1 | awk -F': ' '{print $2}')
if [ -z "$IFACE" ]; then
    echo "[!] No ethernet interface found"
    ip link show
    exit 1
fi
echo "    Interface: $IFACE"

ip addr flush dev "$IFACE" 2>/dev/null || true
ip route flush dev "$IFACE" 2>/dev/null || true
ip addr add "$MY_IP/18" dev "$IFACE" 2>/dev/null || true
ip link set "$IFACE" up
ip route del default 2>/dev/null || true
ip route add default via "$GATEWAY"
echo "nameserver $GATEWAY" > /etc/resolv.conf

echo -n "    Testing Gateway... "
if ping -c 1 -W 3 "$GATEWAY" > /dev/null 2>&1; then
    echo "OK"
else
    echo "FAILED — is Whonix Gateway running?"
    exit 1
fi

echo -n "    Testing Tor connection... "
TOR=$(curl -s --max-time 15 https://check.torproject.org/api/ip 2>/dev/null)
if echo "$TOR" | grep -q "IsTor.*true"; then
    IP=$(echo "$TOR" | grep -o '"IP":"[^"]*"' | cut -d'"' -f4)
    echo "OK (exit IP: $IP)"
else
    echo "WARNING — Tor may not be active, continuing anyway"
fi

# ── 2. Install dependencies ──────────────────────────
echo ""
echo "[2/4] Installing dependencies..."
apt-get update -qq 2>/dev/null || true
apt-get install -y -qq git python3 python3-pip 2>/dev/null || true
pip3 install aiohttp requests rich --break-system-packages -q 2>/dev/null \
    || pip3 install aiohttp requests rich -q 2>/dev/null \
    || echo "    pip install skipped (may already be installed)"

# ── 3. Clone / update repo ──────────────────────────
echo ""
echo "[3/4] Downloading WebRecon..."
if [ -d "$DIR/.git" ]; then
    echo "    Updating existing installation..."
    git -C "$DIR" pull -q
else
    git clone -q "$REPO" "$DIR"
fi
chmod +x "$DIR/run.sh"
echo "    Installed to: $DIR"

# ── 4. Persist network config ────────────────────────
cat > /etc/network/interfaces.d/whonix.conf <<EOF
auto $IFACE
iface $IFACE inet static
    address $MY_IP
    netmask 255.255.192.0
    gateway $GATEWAY
    dns-nameservers $GATEWAY
EOF

# ── 5. Run scanner ───────────────────────────────────
echo ""
echo "[4/4] Ready!"
echo "================================================"
echo ""

if [ -n "$1" ]; then
    TARGET="$1"
else
    read -rp "Enter target URL (e.g. https://example.com): " TARGET
fi

if [ -z "$TARGET" ]; then
    echo "[!] No target specified."
    echo "    Usage: bash kali_start.sh https://example.com"
    exit 1
fi

echo ""
echo "Starting scan: $TARGET"
echo "Report will be saved to: $DIR/reports/"
echo ""
cd "$DIR"
python3 scanner.py "$TARGET"
