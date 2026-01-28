#!/bin/bash
# Start Suricata IDS with proper alert logging

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Suricata IDS ==="

# Check if Mininet is running
if ! pgrep -f "mininet" > /dev/null; then
    echo "❌ Error: Mininet is not running!"
    echo "Start the topology first: sudo ./scripts/start_topology.sh"
    exit 1
fi

# Get the PID of the suricata host process
SURICATA_PID=$(ps aux | grep -E "mininet:suricata" | grep -v grep | awk '{print $2}' | head -1)

if [ -z "$SURICATA_PID" ]; then
    echo "❌ Error: Cannot find Suricata host in Mininet!"
    echo "Make sure topology is running with Suricata host."
    exit 1
fi

echo "✓ Found Suricata host (PID: $SURICATA_PID)"

# Clear old alert logs - Suricata writes to /tmp/ as configured in suricata.yaml
sudo rm -f /tmp/suricata-alerts.json /tmp/suricata-fast.log /tmp/suricata-stats.log
sudo touch /tmp/suricata-alerts.json
sudo chmod 666 /tmp/suricata-alerts.json

echo "✓ Alert log cleared: /tmp/suricata-alerts.json"

# Clean up any old PID files and existing Suricata daemon processes (not this script!)
sudo rm -f /var/run/suricata.pid
# Use pkill with full path match to avoid killing this script
sudo pkill -9 -x suricata 2>/dev/null || true
sleep 1

IFACE="suricata-eth0"
echo "✓ Interface: $IFACE (inside Mininet namespace)"
echo "✓ Config: $PROJECT_DIR/config/suricata.yaml"
echo ""
echo "Starting Suricata in FOREGROUND mode..."
echo "Press Ctrl+C to stop Suricata"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Suricata IDS is now running. Alerts will be logged to:"
echo "  - /tmp/suricata-alerts.json (JSON format)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run Suricata in FOREGROUND mode (no -D flag) in the Mininet namespace
# Do NOT use -l flag so Suricata writes to paths in suricata.yaml (/tmp/)
sudo nsenter -t $SURICATA_PID -n suricata \
    -c "$PROJECT_DIR/config/suricata.yaml" \
    -i $IFACE \
    --init-errors-fatal

# This code runs when Suricata exits (Ctrl+C)
echo ""
echo "✅ Suricata stopped"