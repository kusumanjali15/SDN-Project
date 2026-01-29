# SDN-IDS Testing Guide

Quick reference for testing the complete SDN + Suricata IDS integration.

## 🚀 Quick Start (3 Terminals Required)

### Terminal 1: Start Ryu Controller
```bash
cd /home/kali/sdn-project
./scripts/start_controller.sh
```
**Expected output:** "Switch connected: DPID=1" (and DPIDs 2-5)

### Terminal 2: Start Mininet Topology
```bash
cd /home/kali/sdn-project
sudo ./scripts/start_topology.sh
```
**Expected output:** Mininet CLI prompt `mininet>`  
**Key info:** "Suricata connected to S1 on port: 1"

### Terminal 3: Start Suricata IDS
```bash
cd /home/kali/sdn-project
./scripts/start_suricata.sh
```
**Expected output:** Suricata running in daemon mode

---

## 🧪 Test Scenarios

### 1. Basic Connectivity Test (Within VLAN)
In Mininet CLI (Terminal 2):
```
mininet> h1 ping -c 3 h3
```
**Expected:** ✅ Successful pings (both in VLAN1: 10.0.1.x)

```
mininet> h2 ping -c 3 h4
```
**Expected:** ✅ Successful pings (both in VLAN2: 10.0.2.x)

### 2. Cross-VLAN Test
```
mininet> h1 ping -c 3 h2
```
**Expected:** ❌ "Network is unreachable" (no router configured)

### 3. ICMP Flood Detection (Trigger IDS Alert)
```
mininet> h1 ping -c 25 -i 0.1 h3
```
**What happens:**
- 25 pings sent rapidly (0.1 sec interval = very fast)
- Suricata detects >20 pings in 5 seconds
- Alert generated with SID 1000002 (priority 1)
- Alert saved to `/tmp/suricata-alerts.json`
- **Controller automatically blocks h1's IP (10.0.1.1)**

**Expected Controller Output:**
```
Alert detected: SID=1000002, Priority=1, SrcIP=10.0.1.1, Signature=ICMP Flood Attack Detected
HIGH PRIORITY ALERT (Priority 1) from 10.0.1.1 - Initiating block
Installed block rules for 10.0.1.1 on DPID=1
Installed block rules for 10.0.1.1 on DPID=2
...
BLOCKED IP 10.0.1.1 on 5 switches
```

**Monitor alerts in Terminal 4:**
```bash
./scripts/monitor.sh
```

### 4. Manual IP Blocking Test
From Ryu controller logs, note an active host IP (e.g., 10.0.1.1), then manually block it:

In Terminal 5:
```bash
echo "10.0.1.1" | sudo tee -a /tmp/blocked_ips.txt
# Restart controller to load blocked IPs
```

Back in Mininet:
```
mininet> h1 ping -c 3 h3
```
**Expected:** 100% packet loss (h1's IP 10.0.1.1 is blocked)

---

## 📊 Monitoring Commands

### Check Suricata Alerts (Live)
```bash
tail -f /tmp/suricata-alerts.json | jq '{time: .timestamp, alert: .alert.signature, severity: .alert.severity, src: .src_ip, dst: .dest_ip}'
```

### Check Blocked IPs
```bash
cat /tmp/blocked_ips.txt
```

### Check Suricata Port Mapping
```bash
cat /tmp/suricata_port.txt
```
**Format:** `dpid,port` (e.g., `1,1` means DPID 1, port 1)

### View OVS Switch Configuration
```bash
sudo ovs-vsctl show
```

### View Controller Logs
Check Terminal 1 for real-time packet processing logs showing:
- `packet in dpid=X src=... dst=...` 
- `Mirroring to Suricata on port X`
- `Blocked IP: X.X.X.X`

### View Network Topology
In Mininet CLI:
```
mininet> net
mininet> links
mininet> dump
```

---

## 🎯 Expected IDS Alerts

| Rule | SID | Priority | Trigger | Description |
|------|-----|----------|---------|-------------|
| ICMP Flood | 1000002 | 1 | 10+ ICMP in 10s | Auto-blocks source IP |
| ICMP Sweep | 1000003 | 2 | 10+ ICMP in 5s | Logged only |
| SYN Scan | 1000010 | 1 | 20+ SYN in 10s | Auto-blocks source IP |
| SSH Brute Force | 1000020 | 1 | 10+ SSH conn in 60s | Auto-blocks source IP |
| SQL Injection | 1000030 | 1 | SQL keywords in HTTP | Auto-blocks source IP |

**Note:** Only priority 1-2 alerts trigger automatic blocking (when alert processing is implemented).

---

## 🧹 Cleanup

### Stop Everything
```bash
# Terminal 2 (Mininet): Press Ctrl+C or type 'exit'
mininet> exit

# Then run cleanup script:
./scripts/cleanup.sh
```

This will:
- Kill Ryu controller
- Kill Suricata processes
- Clean Mininet (`mn -c`)
- Remove temp files
- Restart OVS

---

## 🔧 Troubleshooting

### "No Suricata interface found"
**Cause:** Topology not started  
**Fix:** Start topology BEFORE Suricata (it creates the interface)

### Suricata not detecting traffic
**Cause:** Wrong interface or port mapping  
**Check:**
```bash
cat /tmp/suricata_port.txt  # Should show: 1,1
sudo ovs-vsctl show          # Verify suricata connected to s1
ip link show | grep suricata # Should see suricata-ext interface
```

### No mirroring in controller logs
**Cause:** Suricata port not loaded  
**Check:** Controller logs should show "Loaded Suricata port: DPID=1, Port=1"  
**Fix:** Ensure `/tmp/suricata_port.txt` exists before controller starts

### Pings work but no alerts
**Cause:** Suricata not running or rule threshold not met  
**Check:**
```bash
ps aux | grep suricata
tail /tmp/suricata-fast.log
```
**Fix:** Ensure 10+ pings in <10 seconds for ICMP flood

### "Network is unreachable" between VLANs
**Expected behavior:** VLANs are isolated (no router configured)  
**Fix:** Test within same VLAN (h1↔h3 or h2↔h4)

---

## 📝 Architecture Reminder

```
Traffic Flow:
h1 → S2 → S1 (mirror) → [Suricata on port 1]
              ↓
           Controller (reads alerts, blocks IPs)
```

**Key Points:**
- ALL traffic goes through S1 (main switch)
- S1 mirrors traffic to Suricata on port 1
- Controller applies blocks at priority 100 (higher than MAC learning at priority 1)
- Empty action list = DROP packet (OpenFlow convention)

---

## 🎓 Learning Exercises

1. **Test MAC Learning:** Ping h1→h3, check controller logs for MAC table updates
2. **Verify Mirroring:** Look for "Mirroring to Suricata" in controller logs during pings
3. **Trigger Multiple Alerts:** Try different attack patterns (SSH, port scans)
4. **Custom Rules:** Add new Suricata rules in `config/custom.rules`
5. **Flow Priority:** Use `sudo ovs-ofctl dump-flows s1 -O OpenFlow13` to see installed flows

Happy testing! 🚀
