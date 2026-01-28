#!/bin/bash
# Comprehensive SDN-IDS System Verification

echo "╔════════════════════════════════════════════════════════════╗"
echo "║           SDN-IDS System Verification Tool                ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
WARN=0

check_pass() {
    echo -e "${GREEN}✓${NC} $1"
    ((PASS++))
}

check_fail() {
    echo -e "${RED}✗${NC} $1"
    ((FAIL++))
}

check_warn() {
    echo -e "${YELLOW}⚠${NC} $1"
    ((WARN++))
}

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "1. CHECKING MININET"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if pgrep -f "mininet" > /dev/null; then
    check_pass "Mininet is running"
    
    # Check switches
    SWITCH_COUNT=$(sudo ovs-vsctl list-br | wc -l)
    if [ $SWITCH_COUNT -ge 5 ]; then
        check_pass "Found $SWITCH_COUNT switches"
    else
        check_warn "Expected 5+ switches, found $SWITCH_COUNT"
    fi
else
    check_fail "Mininet is NOT running"
    echo "   → Start with: sudo ./scripts/start_topology.sh"
    FAIL=999  # Critical failure
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "2. CHECKING RYU CONTROLLER"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if pgrep -f "ryu-manager" > /dev/null; then
    check_pass "Ryu controller is running"
    
    # Check if controller is connected to switches
    CONNECTED=$(sudo ovs-vsctl get-controller s1 2>/dev/null)
    if [[ $CONNECTED == *"127.0.0.1"* ]] || [[ $CONNECTED == *"localhost"* ]]; then
        check_pass "Controller connected to switches"
    else
        check_warn "Controller connection unclear: $CONNECTED"
    fi
else
    check_fail "Ryu controller is NOT running"
    echo "   → Start with: ./scripts/start_controller.sh"
    FAIL=999  # Critical failure
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "3. CHECKING SURICATA IDS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if pgrep suricata > /dev/null; then
    SURICATA_IFACE=$(ps aux | grep suricata | grep "\-i" | grep -oP "\-i \K[a-z0-9\-]+" | head -1)
    check_pass "Suricata is running on interface: $SURICATA_IFACE"
    
    # Check if Suricata is in correct namespace
    SURICATA_PID=$(pgrep suricata | head -1)
    NAMESPACE=$(sudo ls -l /proc/$SURICATA_PID/ns/net 2>/dev/null | awk '{print $NF}')
    echo "   Namespace: $NAMESPACE"
else
    check_fail "Suricata is NOT running"
    echo "   → Start with: ./scripts/start_suricata.sh"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "4. CHECKING PORT MIRRORING"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if mirror exists
if sudo ovs-vsctl list mirror | grep -q "name.*suricata-mirror"; then
    check_pass "OVS mirror 'suricata-mirror' configured"
    
    # Check mirror configuration
    OUTPUT_PORT=$(sudo ovs-vsctl list mirror | grep "output_port" | grep -oP "\d+")
    SELECT_ALL=$(sudo ovs-vsctl list mirror | grep "select_all" | grep -oP "(true|false)")
    
    if [ "$SELECT_ALL" == "true" ]; then
        check_pass "Mirror set to select_all=true"
    else
        check_warn "Mirror select_all=$SELECT_ALL (should be true)"
    fi
    
    if [ -n "$OUTPUT_PORT" ]; then
        check_pass "Mirror output port: $OUTPUT_PORT"
    fi
    
    # Check statistics
    TX_PACKETS=$(sudo ovs-vsctl list mirror | grep "statistics" | grep -oP "tx_packets=\K[0-9]+")
    if [ -n "$TX_PACKETS" ]; then
        if [ $TX_PACKETS -gt 0 ]; then
            check_pass "Mirror is actively forwarding packets (tx_packets: $TX_PACKETS)"
        else
            check_warn "Mirror configured but no packets mirrored yet (tx_packets: 0)"
        fi
    fi
else
    check_fail "OVS mirror NOT configured"
    echo "   → Run: ./scripts/setup_mirror.sh"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "5. CHECKING SURICATA CONFIGURATION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check port mapping file
if [ -f /tmp/suricata_port.txt ]; then
    MAPPING=$(cat /tmp/suricata_port.txt)
    check_pass "Suricata port mapping exists: $MAPPING"
else
    check_fail "Suricata port mapping file not found (/tmp/suricata_port.txt)"
fi

# Check rules file
RULES_FILE="$HOME/sdn-project/config/custom.rules"
if [ -f "$RULES_FILE" ]; then
    RULE_COUNT=$(grep -c "^alert" "$RULES_FILE" 2>/dev/null)
    check_pass "Found $RULE_COUNT alert rules in custom.rules"
else
    check_warn "Custom rules file not found at $RULES_FILE"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "6. CHECKING ALERT FILES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check eve.json (main alert file)
if [ -f /var/log/suricata/eve.json ]; then
    FILE_SIZE=$(stat -c%s /var/log/suricata/eve.json)
    ALERT_COUNT=$(grep -c '"event_type":"alert"' /var/log/suricata/eve.json 2>/dev/null || echo "0")
    check_pass "Alert file exists: /var/log/suricata/eve.json"
    echo "   Size: $FILE_SIZE bytes, Alerts: $ALERT_COUNT"
else
    check_warn "Alert file not found (will be created on first alert)"
fi

# Check symlink
if [ -L /tmp/suricata-alerts.json ]; then
    TARGET=$(readlink /tmp/suricata-alerts.json)
    check_pass "Alert symlink exists: /tmp/suricata-alerts.json → $TARGET"
else
    check_warn "Alert symlink not found at /tmp/suricata-alerts.json"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "7. CHECKING BLOCKING FUNCTIONALITY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f /tmp/blocked_ips.txt ]; then
    BLOCKED_COUNT=$(grep -v '^#' /tmp/blocked_ips.txt | grep -v '^$' | wc -l)
    if [ $BLOCKED_COUNT -gt 0 ]; then
        check_pass "Blocked IPs file exists with $BLOCKED_COUNT IPs"
        echo "   Blocked IPs:"
        grep -v '^#' /tmp/blocked_ips.txt | grep -v '^$' | while read ip; do
            echo "     - $ip"
        done
    else
        check_pass "Blocked IPs file exists (empty)"
    fi
else
    check_warn "Blocked IPs file not created yet"
fi

# Check for blocking flow rules
BLOCK_RULES=$(sudo ovs-ofctl dump-flows s1 -O OpenFlow13 2>/dev/null | grep "priority=200" | wc -l)
if [ $BLOCK_RULES -gt 0 ]; then
    check_pass "Found $BLOCK_RULES blocking flow rules (priority=200)"
else
    check_warn "No blocking flow rules found (none blocked yet)"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "8. TESTING PACKET CAPTURE"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ $FAIL -eq 999 ]; then
    check_fail "Skipping packet capture test (critical services not running)"
else
    SURICATA_PID=$(ps aux | grep -E "mininet:suricata" | grep -v grep | awk '{print $2}' | head -1)
    if [ -n "$SURICATA_PID" ]; then
        echo "   Testing for 3 seconds..."
        PACKET_COUNT=$(timeout 3 sudo nsenter -t $SURICATA_PID -n tcpdump -i suricata-eth0 -c 10 -n 2>&1 | grep -c "IP" || echo "0")
        if [ $PACKET_COUNT -gt 0 ]; then
            check_pass "Packets are being captured ($PACKET_COUNT packets in 3 seconds)"
        else
            check_warn "No packets captured (try: h1 ping h2 in Mininet CLI)"
        fi
    else
        check_warn "Cannot access Suricata namespace for packet test"
    fi
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    VERIFICATION SUMMARY                   ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}Passed:  $PASS${NC}"
echo -e "${YELLOW}Warnings: $WARN${NC}"
echo -e "${RED}Failed:  $FAIL${NC}"
echo ""

if [ $FAIL -eq 0 ] && [ $WARN -eq 0 ]; then
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║          ✅ SYSTEM STATUS: FULLY OPERATIONAL ✅           ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🎯 System is ready for attack detection testing!"
    echo ""
    echo "Test commands:"
    echo "  1. Generate ICMP flood:"
    echo "     mininet> h1 ping -c 25 -i 0.2 h3"
    echo ""
    echo "  2. Monitor alerts in real-time:"
    echo "     ./scripts/monitor.sh"
    echo ""
    echo "  3. Check blocked IPs:"
    echo "     cat /tmp/blocked_ips.txt"
    echo ""
elif [ $FAIL -eq 999 ]; then
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║     ❌ SYSTEM STATUS: CRITICAL SERVICES NOT RUNNING ❌    ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🔧 Start services in this order:"
    echo "  1. ./scripts/start_controller.sh"
    echo "  2. sudo ./scripts/start_topology.sh"
    echo "  3. ./scripts/start_suricata.sh"
    echo "  4. ./scripts/setup_mirror.sh"
    echo ""
elif [ $FAIL -gt 0 ]; then
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║        ⚠️  SYSTEM STATUS: ISSUES DETECTED ⚠️             ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "Review the failures above and fix them before testing."
    echo ""
else
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║      ⚠️  SYSTEM STATUS: OPERATIONAL WITH WARNINGS ⚠️      ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo ""
    echo "System should work but review warnings for optimal performance."
    echo ""
fi