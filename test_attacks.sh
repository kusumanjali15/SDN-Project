#!/bin/bash
# DDoS Attack Testing Scripts for SDN-IDS Integration

echo "=== SDN-IDS DDoS Attack Testing ==="
echo ""
echo "This script provides commands to test different DDoS attacks"
echo "Run these commands from your Mininet CLI (mininet> prompt)"
echo ""
echo "Prerequisites:"
echo "- Controller running"
echo "- Topology running"  
echo "- Suricata running"
echo ""

cat << 'EOF'

## 1. ICMP Flood Attack (Easiest to Test)
## Sends 25 rapid pings in ~2.5 seconds
## Triggers: SID 1000002 (20 pings in 5 sec threshold)

mininet> h1 ping -c 25 -i 0.1 h3

Expected: h1 (10.0.1.1) will be automatically blocked
Verify with: h1 ping -c 3 h3  (should fail with 100% loss)


## 2. SYN Flood Attack (Port Scan Simulation)
## Uses hping3 to send SYN packets rapidly
## Triggers: SID 1000050 (30 SYN packets in 2 sec)

mininet> h1 cmd hping3 -S -p 80 -c 40 --faster 10.0.1.3

Expected: h1 (10.0.1.1) will be blocked for SYN flood attack
Note: Requires hping3 installed (sudo apt install hping3)


## 3. TCP Connection Flood
## Opens many TCP connections rapidly
## Triggers: SID 1000052 (40 connections in 3 sec)

mininet> h1 cmd for i in {1..50}; do (nc -z 10.0.1.3 80 &); done

Expected: h1 blocked for connection flooding


## 4. UDP Flood Attack
## Sends many UDP packets
## Triggers: SID 1000051 (50 UDP packets in 2 sec)

mininet> h1 cmd hping3 --udp -p 53 -c 60 --faster 10.0.1.3

Expected: h1 blocked for UDP flooding
Note: Requires hping3


## 5. Multi-Source DDoS (Distributed Attack)
## Multiple hosts attacking same target

mininet> h1 ping -c 25 -i 0.1 h3 &
mininet> h5 ping -c 25 -i 0.1 h3 &
mininet> h7 ping -c 25 -i 0.1 h3 &

Expected: All attackers (h1, h5, h7) get blocked


## 6. Port Scan Attack
## Scans multiple ports (reconnaissance)
## Triggers: SID 1000010 (20 SYN packets in 10 sec)

mininet> h1 cmd nmap -sS -p 1-100 10.0.1.3

Expected: h1 blocked for port scanning
Note: Requires nmap installed


## MONITORING COMMANDS (Run in separate terminal):

# Watch controller for blocking events:
tail -f /tmp/controller_output.log | grep -E "(ALERT|BLOCKED|HIGH PRIORITY)"

# Watch Suricata alerts in real-time:
tail -f /tmp/suricata-alerts.json | jq -r 'select(.event_type=="alert") | {time: .timestamp, alert: .alert.signature, src: .src_ip, dst: .dest_ip}'

# Check blocked IPs:
cat /tmp/blocked_ips.txt

# Check specific alerts:
grep -E 'SID=(1000002|1000050|1000051|1000052)' /tmp/suricata-alerts.json | tail -5


## CLEANUP (After testing):

# Clear blocked IPs and restart:
sudo rm /tmp/blocked_ips.txt
sudo ./scripts/cleanup.sh
./scripts/start_controller.sh (Terminal 1)
sudo ./scripts/start_topology.sh (Terminal 2)
./scripts/start_suricata.sh (Terminal 3)


## RECOMMENDED TESTING ORDER:

1. Start with ICMP Flood (easiest, works without extra tools)
2. Try Multi-Source DDoS to see multiple IPs blocked
3. If hping3 available, test SYN and UDP floods
4. Advanced: Port scanning with nmap

EOF
