#!/bin/bash
# Configure OVS Port Mirroring for Suricata

echo "=== Configuring OVS Port Mirroring ==="

# Check if Mininet is running
if ! pgrep -f "mininet" > /dev/null; then
    echo "❌ Error: Mininet is not running!"
    echo "Start the topology first: sudo ./scripts/start_topology.sh"
    exit 1
fi

# Check if Suricata port info exists
if [ ! -f /tmp/suricata_port.txt ]; then
    echo "❌ Error: Suricata port info not found!"
    echo "Make sure topology has started and created /tmp/suricata_port.txt"
    exit 1
fi

# Read Suricata port configuration
SURICATA_INFO=$(cat /tmp/suricata_port.txt)
DPID=$(echo $SURICATA_INFO | cut -d',' -f1)
SURICATA_PORT=$(echo $SURICATA_INFO | cut -d',' -f2)

echo "✓ Suricata configuration: DPID=$DPID, Port=$SURICATA_PORT"

# Remove existing mirror if it exists
sudo ovs-vsctl clear bridge s1 mirrors 2>/dev/null
echo "✓ Cleaned up old mirror configuration"

# Get the interface name for the Suricata port
SURICATA_IFACE=$(sudo ovs-ofctl -O OpenFlow13 show s1 | grep "^ ${SURICATA_PORT}(" | awk '{print $1}' | cut -d'(' -f2 | cut -d')' -f1)

if [ -z "$SURICATA_IFACE" ]; then
    echo "❌ Error: Could not find interface for port $SURICATA_PORT"
    echo ""
    echo "Available ports on s1:"
    sudo ovs-ofctl -O OpenFlow13 show s1
    exit 1
fi

echo "✓ Found Suricata interface: $SURICATA_IFACE (port $SURICATA_PORT)"
echo ""
echo "Creating port mirror to Suricata..."
echo "  Method: select-all traffic"
echo "  Output interface: $SURICATA_IFACE"
echo ""

# Method 1: Try using select-all with proper port reference
# Get all other ports to mirror FROM
ALL_PORTS=$(sudo ovs-ofctl show s1 -O OpenFlow13 | grep -oP '^\s+\d+(?=\()' | grep -v "^${SURICATA_PORT}$" | tr '\n' ',' | sed 's/,$//')

if [ -n "$ALL_PORTS" ]; then
    echo "  Mirroring ports: $ALL_PORTS → port $SURICATA_PORT"
fi

# Get the Port UUID for the Suricata interface (needed for output-port)
PORT_UUID=$(sudo ovs-vsctl get port $SURICATA_IFACE _uuid)

if [ -z "$PORT_UUID" ]; then
    echo "❌ Error: Could not get UUID for port $SURICATA_IFACE"
    exit 1
fi

echo "  Port UUID: $PORT_UUID"

# Create mirror with proper output-port setting
# This mirrors ALL traffic on the bridge to the Suricata port
sudo ovs-vsctl \
    -- --id=@m create mirror name=suricata-mirror select-all=true output-port=$PORT_UUID \
    -- set bridge s1 mirrors=@m

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Port mirroring configured successfully!"
    echo ""
    
    # Wait a moment for configuration to apply
    sleep 1
    
    # Verify the configuration
    echo "📊 Mirror Configuration:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    sudo ovs-vsctl list mirror
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # Check if mirror is active
    MIRROR_CHECK=$(sudo ovs-vsctl list mirror | grep "name" | grep "suricata-mirror")
    if [ -n "$MIRROR_CHECK" ]; then
        echo "✅ Mirror 'suricata-mirror' is active"
    else
        echo "⚠️  Warning: Mirror created but not showing in list"
    fi
    
    echo ""
    echo "✅ Setup Complete!"
    echo ""
    echo "🧪 Test Commands:"
    echo "  1. Generate traffic in Mininet CLI:"
    echo "     mininet> h1 ping -c 10 h2"
    echo ""
    echo "  2. Check if Suricata receives packets:"
    echo "     SURICATA_PID=\$(ps aux | grep 'mininet:suricata' | grep -v grep | awk '{print \$2}' | head -1)"
    echo "     sudo nsenter -t \$SURICATA_PID -n tcpdump -i suricata-eth0 -c 10 -n"
    echo ""
    echo "  3. Monitor Suricata alerts:"
    echo "     tail -f /var/log/suricata/eve.json | grep alert"
    echo ""
    echo "  4. Or use the monitor script:"
    echo "     ./scripts/monitor.sh"
    echo ""
    echo "  5. Check mirror statistics (after traffic):"
    echo "     sudo ovs-vsctl list mirror | grep statistics"
    echo ""
else
    echo ""
    echo "❌ Failed to configure port mirroring"
    echo ""
    echo "🔍 Troubleshooting:"
    echo ""
    echo "1. Check OVS is running:"
    echo "   sudo systemctl status openvswitch-switch"
    echo ""
    echo "2. Check bridge exists:"
    echo "   sudo ovs-vsctl list-br"
    echo ""
    echo "3. Show all ports on s1:"
    echo "   sudo ovs-ofctl show s1"
    echo ""
    echo "4. List all interfaces:"
    echo "   sudo ovs-vsctl list interface"
    echo ""
    echo "5. Try manual configuration:"
    echo "   sudo ovs-appctl bridge/dump-flows s1"
    echo ""
    exit 1
fi