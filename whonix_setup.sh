#!/bin/bash
# Auto-configure Kali to route through Whonix Gateway

GATEWAY="10.152.152.10"
MY_IP="10.152.152.20"
NETMASK="18"

echo "[*] Detecting network interface..."
IFACE=$(ip link show | grep -E "^[0-9]+: (eth|ens|enp|eno)" | head -1 | awk -F': ' '{print $2}')

if [ -z "$IFACE" ]; then
    echo "[!] No ethernet interface found. Available interfaces:"
    ip link show
    exit 1
fi
echo "[+] Found interface: $IFACE"

echo "[*] Checking current IP..."
CURRENT_IP=$(ip addr show "$IFACE" | grep "inet " | awk '{print $2}')
echo "[+] Current IP: ${CURRENT_IP:-none}"

echo "[*] Flushing interface..."
ip addr flush dev "$IFACE" 2>/dev/null
ip route flush dev "$IFACE" 2>/dev/null

echo "[*] Setting IP $MY_IP/$NETMASK..."
ip addr add "$MY_IP/$NETMASK" dev "$IFACE"
ip link set "$IFACE" up

echo "[*] Setting default route via $GATEWAY..."
ip route del default 2>/dev/null
ip route add default via "$GATEWAY"

echo "[*] Setting DNS..."
echo "nameserver $GATEWAY" > /etc/resolv.conf

echo "[*] Testing Gateway ping..."
if ping -c 2 -W 3 "$GATEWAY" > /dev/null 2>&1; then
    echo "[+] Gateway reachable!"
else
    echo "[!] Gateway NOT reachable. Check VirtualBox internal network name = 'Whonix'"
    exit 1
fi

echo "[*] Testing Tor connectivity..."
TOR_CHECK=$(curl -s --max-time 15 https://check.torproject.org/api/ip 2>/dev/null)
if echo "$TOR_CHECK" | grep -q "IsTor.*true"; then
    IP=$(echo "$TOR_CHECK" | grep -o '"IP":"[^"]*"' | cut -d'"' -f4)
    echo "[+] Connected via Tor! Exit IP: $IP"
else
    echo "[!] Tor check failed or slow. Try manually: curl https://check.torproject.org/api/ip"
fi

echo ""
echo "[*] Making config persistent..."
cat > /etc/network/interfaces.d/whonix.conf <<EOF
auto $IFACE
iface $IFACE inet static
    address $MY_IP
    netmask 255.255.192.0
    gateway $GATEWAY
    dns-nameservers $GATEWAY
EOF

echo "[+] Done! Config saved to /etc/network/interfaces.d/whonix.conf"
echo "[+] Run 'curl https://check.torproject.org/api/ip' to verify anytime"
