#!/bin/bash
# Quick System Status Check

echo "=== SDN-IDS Quick Status ==="
echo ""

# Controller
if pgrep -f "ryu-manager" > /dev/null; then
    echo "✓ Controller: RUNNING"
else
    echo "✗ Controller: NOT RUNNING"
fi

# Mininet
if pgrep -f "mininet" > /dev/null; then
    echo "✓ Mininet: RUNNING"
else
    echo "✗ Mininet: NOT RUNNING"
fi

# Suricata
SURICATA_COUNT=$(ps aux | grep "suricata -c" | grep -v grep | wc -l)
if [ $SURICATA_COUNT -gt 0 ]; then
    echo "✓ Suricata: RUNNING ($SURICATA_COUNT process(es))"
else
    echo "✗ Suricata: NOT RUNNING"
fi

# OVS Mirror
if sudo ovs-vsctl list mirror 2>/dev/null | grep -q "suricata-mirror"; then
    echo "✓ OVS Mirror: CONFIGURED"
else
    echo "✗ OVS Mirror: NOT CONFIGURED"
fi

# Blocked IPs
if [ -f /tmp/blocked_ips.txt ]; then
    BLOCKED_COUNT=$(wc -l < /tmp/blocked_ips.txt)
    echo "✓ Blocked IPs: $BLOCKED_COUNT"
else
    echo "○ Blocked IPs: 0 (file not created yet)"
fi

# Alerts
if [ -f /tmp/suricata-alerts.json ]; then
    ALERT_COUNT=$(grep -c "event_type" /tmp/suricata-alerts.json 2>/dev/null || echo "0")
    echo "✓ Alerts: $ALERT_COUNT"
else
    echo "○ Alerts: 0 (file not created yet)"
fi

echo ""
echo "=== Ready to Test ==="
echo "Run in Mininet CLI: h1 ping -c 25 -i 0.2 h3"
echo "Monitor: ./scripts/monitor.sh"
echo ""
