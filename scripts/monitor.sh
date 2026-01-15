#!/bin/bash
# Monitor Suricata Alerts

echo "=== Suricata Alert Monitor ==="
echo "Watching: /tmp/suricata-alerts.json"
echo "Press Ctrl+C to stop"
echo ""

if command -v jq &> /dev/null; then
    tail -f /tmp/suricata-alerts.json 2>/dev/null | while read line; do
        [ -n "$line" ] && echo "$line" | jq -C '{time: .timestamp, alert: .alert.signature, severity: .alert.severity, src: .src_ip, dst: .dest_ip}' 2>/dev/null
    done
else
    tail -f /tmp/suricata-alerts.json 2>/dev/null
fi
