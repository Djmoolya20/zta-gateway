#!/bin/bash
# Attacker Demo Script - Run from ATTACKER machine (different computer)
# Throttled to fit within one 30s scoring window without DoS-ing the gateway
# Usage: ./attacker_demo.sh <GATEWAY_IP>
# Example: ./attacker_demo.sh 192.168.50.1

set -e

GATEWAY="${1:-192.168.50.1}"
echo "=== ZTA Gateway Attacker Demo ==="
echo "Target: $GATEWAY"
echo "This will trigger ALL 4 risk dimensions to demonstrate auto-ban"
echo ""

# Check tools
for cmd in curl dig ping timeout; do
    command -v $cmd >/dev/null || { echo "Missing: $cmd"; exit 1; }
done

# Function to run with timeout and suppress errors
run_bg() { timeout 2 "$@" >/dev/null 2>&1 & }

echo "[1/4] IDENTITY RISK - 7 failed logins (20% weight)"
for i in {1..7}; do
    curl -s -X POST "http://$GATEWAY/login" \
        -d "username=admin&password=wrong$i" \
        -H "Content-Type: application/x-www-form-urlencoded" >/dev/null
    sleep 0.2
done
echo "    Done - Identity risk should be ~75-100"

echo ""
echo "[2/4] NETWORK RISK - Blocklisted domains + suspicious ports (25% weight)"
# Use UNCACHED subdomains to force DNS queries through gateway
for i in {1..3}; do
    dig @"$GATEWAY" "demo-$RANDOM-$i.doubleclick.net" +short +time=1 &
    dig @"$GATEWAY" "demo-$RANDOM-$i.googlesyndication.com" +short +time=1 &
done
# Suspicious ports: telnet(23), SMB(445), RDP(3389), IRC(6667)
for p in 23 445 3389 6667; do
    timeout 0.5 bash -c "cat < /dev/null > /dev/tcp/$GATEWAY/$p" 2>/dev/null &
done
wait
echo "    Done - Network risk should be ~80-100"

echo ""
echo "[3/4] BEHAVIOR RISK - Port sweep (35% weight, HIGHEST)"
# 300 ports over ~10 seconds = 30 ports/sec (throttled)
for p in {1..300}; do
    timeout 0.05 bash -c "cat < /dev/null > /dev/tcp/$GATEWAY/$p" 2>/dev/null &
    # Throttle to ~30/sec to fit in 30s window
    if (( p % 30 == 0 )); then wait; fi
done
wait
echo "    Done - Behavior risk should spike to 90-100"

echo ""
echo "[4/4] BEHAVIOR RISK - DNS flood + large packets"
for i in {1..50}; do
    dig @"$GATEWAY" "flood-$RANDOM-$i.doubleclick.net" +short +time=1 &
done
for i in {1..20}; do
    ping -c 1 -s 1400 "$GATEWAY" -W 1 >/dev/null 2>&1 &
done
wait
echo "    Done - Additional behavior + network spikes"

echo ""
echo "=== ATTACK COMPLETE ==="
echo "Check the admin dashboard at http://$GATEWAY/admin within 30 seconds"
echo "Expected: Device status -> BANNED (composite risk >= 70)"
echo ""
echo "If not banned yet:"
echo "  - Wait for scoring window (runs every 30s)"
echo "  - Check baseline learning: first 10 min = learning mode (behavior capped at 5)"
echo "  - Run integration test for guaranteed demo: python tests/test_integration.py"