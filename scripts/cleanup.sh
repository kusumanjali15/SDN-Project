#!/bin/bash
# Cleanup all SDN components

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
sudo rm -f /tmp/suricata_port.txt /tmp/suricata-alerts.json /tmp/suricata-fast.log

# Restart OVS
sudo systemctl restart openvswitch-switch 2>/dev/null

echo "Done!"
