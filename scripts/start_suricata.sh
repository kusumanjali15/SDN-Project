#!/bin/bash
# Start Suricata IDS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Suricata IDS ==="

# Check if Mininet is running
if ! pgrep -f "mininet" > /dev/null; then
    echo "Error: Mininet is not running!"
    echo "Start the topology first: sudo ./scripts/start_topology.sh"
    exit 1
fi

# Get the PID of the suricata host process
SURICATA_PID=$(ps aux | grep -E "mininet:suricata" | grep -v grep | awk '{print $2}' | head -1)

if [ -z "$SURICATA_PID" ]; then
    echo "Error: Cannot find Suricata host in Mininet!"
    echo "Make sure topology is running with Suricata host."
    exit 1
fi

# Clear old logs
sudo rm -f /tmp/suricata-alerts.json /tmp/suricata-fast.log
sudo touch /tmp/suricata-alerts.json /tmp/suricata-fast.log

# Clean up any old PID files and existing Suricata daemons
sudo rm -f /var/run/suricata.pid
# Kill any existing Suricata processes in the namespace (but not this script)
sudo nsenter -t $SURICATA_PID -n killall -9 suricata 2>/dev/null || true
sleep 1

IFACE="suricata-eth0"
echo "Interface: $IFACE (inside Mininet namespace)"
echo "Config: $PROJECT_DIR/config/suricata.yaml"
echo ""
echo "Starting Suricata in daemon mode..."

# Run Suricata in daemon mode in the Mininet namespace using nsenter
sudo nsenter -t $SURICATA_PID -n suricata -c "$PROJECT_DIR/config/suricata.yaml" -i $IFACE -D --init-errors-fatal

sleep 2
# Verify Suricata is running
if pgrep -f "suricata.*suricata-eth0" > /dev/null; then
    echo "✓ Suricata started successfully"
    echo "✓ Monitor alerts: ./scripts/monitor.sh"
else
    echo "✗ Failed to start Suricata"
    exit 1
fi
