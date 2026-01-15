#!/bin/bash
# Start Suricata IDS

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Suricata IDS ==="

# Check interface (try suricata-ext first, then suricata-tap)
if ip link show suricata-ext > /dev/null 2>&1; then
    IFACE="suricata-ext"
elif ip link show suricata-tap > /dev/null 2>&1; then
    IFACE="suricata-tap"
else
    echo "Error: No Suricata interface found!"
    echo "Start the topology first: ./start_topology.sh"
    exit 1
fi

# Clear old logs
sudo rm -f /tmp/suricata-alerts.json /tmp/suricata-fast.log
sudo touch /tmp/suricata-alerts.json /tmp/suricata-fast.log

echo "Interface: $IFACE"
echo "Config: $PROJECT_DIR/config/suricata.yaml"
echo ""

sudo suricata -c "$PROJECT_DIR/config/suricata.yaml" -i $IFACE --init-errors-fatal
