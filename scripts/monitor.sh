#!/bin/bash
# Monitor Suricata Alerts - ROBUST VERSION

echo "=== Suricata Alert Monitor (Merged IoT-SDN) ==="
echo "Watching: /tmp/eve.json"
echo "Press Ctrl+C to stop"
echo ""

ALERT_FILE="/tmp/eve.json"

if [ ! -f "$ALERT_FILE" ]; then
    echo "⚠️  Alert file not found. Waiting..."
    echo ""
fi

# Monitor with error handling
tail -f "$ALERT_FILE" 2>/dev/null | while IFS= read -r line; do
    if [ -n "$line" ] && [[ "$line" == *"}"* ]]; then
        if echo "$line" | grep -q '"event_type":"alert"'; then
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            if command -v jq &> /dev/null; then
                echo "$line" | jq -C 'select(.event_type == "alert") | {
                    time: .timestamp,
                    severity: .alert.severity,
                    signature: .alert.signature,
                    sid: .alert.signature_id,
                    src: .src_ip,
                    dst: .dest_ip,
                    proto: .proto
                }' 2>/dev/null || echo "$line"
            else
                echo "$line" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); print(f\"Alert: {d['alert']['signature']} | Src: {d['src_ip']} | Dst: {d['dest_ip']} | Severity: {d['alert']['severity']}\")" 2>/dev/null || echo "$line"
            fi
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        fi
    fi
done