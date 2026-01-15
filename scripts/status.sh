#!/bin/bash
# Quick status check

echo "=== SDN Status ==="
echo ""

# TAP interface
echo -n "TAP Interface: "
ip link show suricata-tap > /dev/null 2>&1 && echo "✓" || echo "✗"

# Suricata port file
echo -n "Port Config:   "
[ -f /tmp/suricata_port.txt ] && echo "✓ ($(cat /tmp/suricata_port.txt))" || echo "✗"

# Suricata process
echo -n "Suricata:      "
pgrep -f "suricata.*suricata-tap" > /dev/null && echo "✓ running" || echo "✗ not running"

# Controller
echo -n "Controller:    "
pgrep -f ryu-manager > /dev/null && echo "✓ running" || echo "✗ not running"

# Flow rules
echo -n "S1 Flows:      "
FLOWS=$(sudo ovs-ofctl dump-flows s1 -O OpenFlow13 2>/dev/null | grep -c "actions=")
[ $FLOWS -gt 0 ] && echo "✓ $FLOWS rules" || echo "✗ none"

# Mirroring
echo -n "Mirroring:     "
sudo ovs-ofctl dump-flows s1 -O OpenFlow13 2>/dev/null | grep -q "output:.*,output:" && echo "✓ active" || echo "✗ inactive"

echo ""
