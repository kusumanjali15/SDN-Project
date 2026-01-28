#!/bin/bash
# Monitor Suricata Alerts in Real-Time

echo "=== Suricata Alert Monitor ==="
echo "Watching: /tmp/eve.json"
echo "Press Ctrl+C to stop"
echo ""

ALERT_FILE="/tmp/eve.json"

# Check if file exists
if [ ! -f "$ALERT_FILE" ]; then
    echo "⚠️  Alert file not found. Waiting for first alert..."
    echo "   Generate traffic to trigger alerts (e.g., h1 ping -c 25 -i 0.2 h3)"
    echo ""
fi

# Function to format and display alerts
format_alert() {
    if command -v jq &> /dev/null; then
        jq -C 'select(.event_type == "alert") | {
            time: .timestamp,
            severity: .alert.severity,
            signature: .alert.signature,
            sid: .alert.signature_id,
            src: .src_ip,
            dst: .dest_ip,
            proto: .proto
        }'
    else
        grep '"event_type":"alert"' | python3 -m json.tool
    fi
}

# Monitor the file
tail -f "$ALERT_FILE" 2>/dev/null | while read line; do
    if [ -n "$line" ]; then
        # Check if this is an alert
        if echo "$line" | grep -q '"event_type":"alert"'; then
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "$line" | format_alert
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        fi
    fi
done