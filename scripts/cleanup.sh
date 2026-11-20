#!/bin/bash
# Cleanup all SDN components
# Usage: ./cleanup.sh [--full]
#   --full: Also clear blocked IPs list (fresh start)
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

echo "=== Cleaning up ==="

# Stop processes
sudo pkill -9 -f ryu-manager 2>/dev/null
sudo pkill -9 suricata 2>/dev/null

# Cleanup Mininet
sudo mn -c 2>/dev/null

# Remove TAP
sudo ovs-vsctl del-port s1 suricata-tap 2>/dev/null
sudo ip link delete suricata-tap 2>/dev/null

# Clean temp files
sudo rm -f ${SDN_RUNTIME_DIR}/suricata_port.txt ${SDN_RUNTIME_DIR}/suricata-alerts.json ${SDN_RUNTIME_DIR}/suricata-fast.log ${SDN_RUNTIME_DIR}/eve.json ${SDN_RUNTIME_DIR}/alert_position.txt

# Full cleanup includes blocked IPs
if [ "$1" == "--full" ]; then
    echo "Full cleanup: clearing blocked IPs"
    sudo rm -f ${SDN_RUNTIME_DIR}/blocked_ips.txt
fi

# Restart OVS
sudo systemctl restart openvswitch-switch 2>/dev/null

echo "Done!"
