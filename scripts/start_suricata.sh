#!/bin/bash
# Start Suricata IDS - UPDATED for Merged IoT-SDN System

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Suricata IDS (Merged IoT-SDN System) ==="

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

# Clear old alert logs
# IMPORTANT: merged_suricata.yaml writes to /tmp/eve.json (not suricata-alerts.json)
sudo rm -f /tmp/eve.json /tmp/fast.log /tmp/suricata.log
sudo touch /tmp/eve.json /tmp/fast.log
sudo chmod 666 /tmp/eve.json /tmp/fast.log

echo "✓ Alert logs cleared:"
echo "  - /tmp/eve.json (main alert file)"
echo "  - /tmp/fast.log (fast format)"

# Clean up any old PID files and existing Suricata processes
sudo rm -f /var/run/suricata.pid
sudo pkill -9 -x suricata 2>/dev/null || true
sleep 1

IFACE="suricata-eth0"
echo "✓ Interface: $IFACE (inside Mininet namespace)"
echo "✓ Config: $PROJECT_DIR/config/suricata.yaml"
echo "✓ Rules: $PROJECT_DIR/config/custom.rules"
echo ""
echo "Starting Suricata in FOREGROUND mode..."
echo "Press Ctrl+C to stop Suricata"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Suricata IDS is now monitoring:"
echo "  - IoT devices (10.0.1.x, 10.0.2.x)"
echo "  - Node-RED veth traffic (172.16.x.x)"
echo "  - All mirrored S1 traffic"
echo ""
echo "Alerts logged to: /tmp/eve.json"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Run Suricata in FOREGROUND mode in the Mininet namespace
# Suricata will write to /tmp/eve.json as configured in merged_suricata.yaml
sudo nsenter -t $SURICATA_PID -n suricata \
    -c "$PROJECT_DIR/config/suricata.yaml" \
    -i $IFACE \
    --init-errors-fatal

# This code runs when Suricata exits (Ctrl+C)
echo ""
echo "✅ Suricata stopped"