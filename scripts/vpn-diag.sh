#!/usr/bin/env bash
# VPN diagnostic script — tests connection quality after connect.
set -euo pipefail

SERVER_IP="157.230.107.26"
WG_CONF="$HOME/.config/cloak/wg0.conf"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
cyan()  { printf '\033[1;36m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }

check() {
    local label="$1"; shift
    printf '  %-22s ' "$label"
    "$@"
}

# --- Pre-flight ---
if [[ "${1:-}" == "up" ]]; then
    cyan "Bringing tunnel up..."
    sudo wg-quick up "$WG_CONF" 2>&1 || true
    sleep 2
elif [[ "${1:-}" == "down" ]]; then
    cyan "Bringing tunnel down..."
    sudo wg-quick down "$WG_CONF" 2>&1 || true
    exit 0
fi

cyan "=== VPN Diagnostics ==="
echo ""

# --- WireGuard interface ---
cyan "[1/6] WireGuard tunnel"
WG_OUT=$(sudo wg show 2>&1) || true
if echo "$WG_OUT" | grep -q "latest handshake"; then
    HS=$(echo "$WG_OUT" | grep "latest handshake" | sed 's/.*: //')
    TX=$(echo "$WG_OUT" | grep "transfer" | sed 's/.*: //')
    check "Handshake:" green "$HS"
    check "Transfer:" echo "$TX"
else
    check "Tunnel:" red "NOT CONNECTED"
    echo ""
    dim "  Run: $0 up"
    exit 1
fi
echo ""

# --- Latency via ICMP ping ---
cyan "[2/6] Latency (ICMP ping to $SERVER_IP)"
PING_OUT=$(ping -c 5 -W 2 "$SERVER_IP" 2>&1) || true
RTT=$(echo "$PING_OUT" | grep "round-trip" | sed 's/.*= //' || echo "failed")
check "RTT (min/avg/max):" echo "$RTT"
LOSS=$(echo "$PING_OUT" | grep "packet loss" | sed 's/.*received, //' | sed 's/,.*//' || echo "?")
check "Packet loss:" echo "$LOSS"
echo ""

# --- DNS resolution ---
cyan "[3/6] DNS resolution (through tunnel)"
DNS_START=$(python3 -c 'import time; print(time.time())')
DNS_RESULT=$(dig +short +time=3 +tries=1 google.com A 2>&1 | head -1) || DNS_RESULT="FAILED"
DNS_END=$(python3 -c 'import time; print(time.time())')
DNS_MS=$(python3 -c "print(f'{($DNS_END - $DNS_START)*1000:.0f} ms')")
check "google.com →" echo "${DNS_RESULT:-empty} (${DNS_MS})"
echo ""

# --- External IP ---
cyan "[4/6] External IP (api.ipify.org via IPv4)"
EXT_START=$(python3 -c 'import time; print(time.time())')
EXT_IP=$(curl -4 -s --connect-timeout 5 --max-time 8 https://api.ipify.org 2>&1) || EXT_IP="FAILED"
EXT_END=$(python3 -c 'import time; print(time.time())')
EXT_MS=$(python3 -c "print(f'{($EXT_END - $EXT_START)*1000:.0f} ms')")
check "Public IP:" echo "${EXT_IP:-unknown} (${EXT_MS})"
echo ""

# --- Throughput estimate (small download) ---
cyan "[5/6] Throughput (10MB download)"
DL_START=$(python3 -c 'import time; print(time.time())')
DL_BYTES=$(curl -4 -s --connect-timeout 5 --max-time 15 -o /dev/null -w '%{size_download}' http://speedtest.tele2.net/10MB.zip 2>&1) || DL_BYTES=0
DL_END=$(python3 -c 'import time; print(time.time())')
DL_SECS=$(python3 -c "print(f'{$DL_END - $DL_START:.2f}')")
DL_MBPS=$(python3 -c "
secs = $DL_END - $DL_START
byt = $DL_BYTES
if secs > 0 and byt > 0:
    print(f'{(byt * 8 / secs / 1_000_000):.2f} Mbps')
else:
    print('N/A')
")
check "Downloaded:" echo "${DL_BYTES} bytes in ${DL_SECS}s → ${DL_MBPS}"
echo ""

# --- MTU check ---
cyan "[6/6] MTU / path check"
MTU_LINE=$(grep -i mtu "$WG_CONF" 2>/dev/null || echo "not set")
check "Client MTU:" echo "$MTU_LINE"
SERVER_MTU=$(ssh -o ConnectTimeout=5 -i ~/.ssh/id_ed25519 root@"$SERVER_IP" 'ip link show wg0 | grep mtu' 2>/dev/null || echo "unreachable")
check "Server MTU:" echo "$SERVER_MTU"
echo ""

cyan "=== Done ==="
