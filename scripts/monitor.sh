#!/bin/bash
# Enhanced Monitor - ML + Suricata Alerts Display
# Shows real-time alerts from both ML detector and Suricata IDS

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     SDN-IDS UNIFIED ALERT MONITOR (ML + Suricata)            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "📡 Monitoring Sources:"
echo "   🤖 ML Detector:  /tmp/ml_alerts.json"
echo "   🛡️  Suricata IDS: /tmp/eve.json"
echo ""
echo "Press Ctrl+C to stop"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""

ML_ALERT_FILE="/tmp/ml_alerts.json"
SURICATA_ALERT_FILE="/tmp/eve.json"

# Create alert files if they don't exist
touch "$ML_ALERT_FILE" 2>/dev/null
touch "$SURICATA_ALERT_FILE" 2>/dev/null

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Function to display ML alerts
display_ml_alert() {
    local line="$1"
    
    if echo "$line" | grep -q '"event_type":"ml_alert"'; then
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}${MAGENTA}🤖 ML DETECTION ALERT${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        # Parse JSON with Python or jq
        if command -v jq &> /dev/null; then
            echo "$line" | jq -r '
                "Time:        \(.timestamp // "N/A")",
                "Source IP:   \(.src_ip // "N/A")",
                "Dest IP:     \(.dest_ip // "N/A")",
                "Attack:      \(.attack_type // "UNKNOWN")",
                "Confidence:  \(.confidence // 0)%",
                "Threat:      \(.threat_score // 0)/100",
                "Protocol:    \(.protocol // "N/A")",
                "Action:      \(if .should_block then "⛔ BLOCKED" else "⚠️  WARNING" end)"
            ' 2>/dev/null || echo "$line"
        else
            # Fallback to Python parsing
            python3 << EOF 2>/dev/null
import json, sys
try:
    data = json.loads('''$line''')
    print(f"Time:        {data.get('timestamp', 'N/A')}")
    print(f"Source IP:   {data.get('src_ip', 'N/A')}")
    print(f"Dest IP:     {data.get('dest_ip', 'N/A')}")
    print(f"Attack:      {data.get('attack_type', 'UNKNOWN')}")
    print(f"Confidence:  {data.get('confidence', 0):.1f}%")
    print(f"Threat:      {data.get('threat_score', 0)}/100")
    print(f"Protocol:    {data.get('protocol', 'N/A')}")
    action = "⛔ BLOCKED" if data.get('should_block') else "⚠️  WARNING"
    print(f"Action:      {action}")
except:
    print("$line")
EOF
        fi
        
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    fi
}

# Function to display Suricata alerts
display_suricata_alert() {
    local line="$1"
    
    if echo "$line" | grep -q '"event_type":"alert"'; then
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "${BOLD}${RED}🛡️  SURICATA IDS ALERT${NC}"
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        # Parse JSON
        if command -v jq &> /dev/null; then
            echo "$line" | jq -r '
                select(.event_type == "alert") | 
                "Time:        \(.timestamp // "N/A")",
                "Signature:   \(.alert.signature // "N/A")",
                "Severity:    \(.alert.severity // "N/A")",
                "SID:         \(.alert.signature_id // "N/A")",
                "Source:      \(.src_ip // "N/A"):\(.src_port // "N/A")",
                "Dest:        \(.dest_ip // "N/A"):\(.dest_port // "N/A")",
                "Protocol:    \(.proto // "N/A")"
            ' 2>/dev/null || echo "$line"
        else
            # Fallback to Python
            python3 << EOF 2>/dev/null
import json, sys
try:
    data = json.loads('''$line''')
    if data.get('event_type') == 'alert':
        alert = data.get('alert', {})
        print(f"Time:        {data.get('timestamp', 'N/A')}")
        print(f"Signature:   {alert.get('signature', 'N/A')}")
        print(f"Severity:    {alert.get('severity', 'N/A')}")
        print(f"SID:         {alert.get('signature_id', 'N/A')}")
        print(f"Source:      {data.get('src_ip', 'N/A')}:{data.get('src_port', 'N/A')}")
        print(f"Dest:        {data.get('dest_ip', 'N/A')}:{data.get('dest_port', 'N/A')}")
        print(f"Protocol:    {data.get('proto', 'N/A')}")
except:
    print("$line")
EOF
        fi
        
        echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo ""
    fi
}

# Monitor both files simultaneously using tail with PID tracking
(tail -f "$ML_ALERT_FILE" 2>/dev/null | while IFS= read -r line; do
    [ -n "$line" ] && display_ml_alert "$line"
done) &
ML_PID=$!

(tail -f "$SURICATA_ALERT_FILE" 2>/dev/null | while IFS= read -r line; do
    [ -n "$line" ] && display_suricata_alert "$line"
done) &
SURICATA_PID=$!

# Trap Ctrl+C to cleanup
trap "kill $ML_PID $SURICATA_PID 2>/dev/null; echo -e '\n\n${GREEN}Monitor stopped.${NC}\n'; exit" INT TERM

# Display initial message
sleep 2
if [ ! -s "$ML_ALERT_FILE" ] && [ ! -s "$SURICATA_ALERT_FILE" ]; then
    echo -e "${BLUE}ℹ️  Waiting for alerts...${NC}"
    echo ""
fi

# Keep script running
wait
