#!/bin/bash
# Monitor Suricata Alerts AND ML Predictions
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

echo "╔════════════════════════════════════════════════════════════╗"
echo "║       SDN-IDS Combined Alert Monitor                       ║"
echo "╠════════════════════════════════════════════════════════════╣"
echo "║  🔍 Suricata: ${SDN_RUNTIME_DIR}/eve.json                                ║"
echo "║  🤖 ML Alerts: ${SDN_RUNTIME_DIR}/ml_alerts.json                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Press Ctrl+C to stop"
echo ""

SURICATA_FILE="${SDN_RUNTIME_DIR}/eve.json"
ML_FILE="${SDN_RUNTIME_DIR}/ml_alerts.json"

# Create files if they don't exist
touch "$SURICATA_FILE" "$ML_FILE" 2>/dev/null

# Use tail with multiple files - simpler approach
tail -f "$SURICATA_FILE" "$ML_FILE" 2>/dev/null | while IFS= read -r line; do
    # Skip empty lines and tail headers
    [[ -z "$line" ]] && continue
    [[ "$line" == "==>"* ]] && continue
    [[ "$line" != *"}"* ]] && continue
    
    # Check if it's a Suricata alert
    if echo "$line" | grep -q '"event_type":"alert"'; then
        echo ""
        echo "┌─────────────────────────────────────────────────────────────┐"
        echo "│ 🛡️  SURICATA ALERT                                          │"
        echo "└─────────────────────────────────────────────────────────────┘"
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
            echo "$line"
        fi
    # Check if it's an ML prediction
    elif echo "$line" | grep -q '"event_type":"ml_prediction"'; then
        echo ""
        echo "┌─────────────────────────────────────────────────────────────┐"
        echo "│ 🤖 ML PREDICTION                                            │"
        echo "└─────────────────────────────────────────────────────────────┘"
        if command -v jq &> /dev/null; then
            echo "$line" | jq -C '{
                time: .timestamp,
                src: .src_ip,
                dst: .dst_ip,
                attack_type: .prediction.attack_type,
                confidence: .prediction.confidence,
                anomaly_score: .prediction.anomaly_score,
                is_anomaly: .prediction.is_anomaly,
                recommendation: .prediction.recommendation
            }' 2>/dev/null || echo "$line"
        else
            echo "$line"
        fi
    fi
done