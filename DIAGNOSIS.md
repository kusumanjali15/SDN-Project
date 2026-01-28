# Problem Diagnosis & Fixes

## Issues Found

### 1. ❌ **Test Rule Conflicting with Threshold Rules**
- **Problem**: Test rule `SID 1000100` (h1→h3) with priority 3 was matching BEFORE the ICMP flood rule
- **Impact**: ICMP Flood rule (SID 1000002, priority 1) never triggered because test rule matched first
- **Result**: Only 1 alert generated (SID 1000100, severity 3) which won't trigger blocking
- **Fix**: Commented out test rules SID 1000100 and 1000101 in [custom.rules](config/custom.rules)

### 2. ❌ **Broken Monitor Script**
- **Problem**: Monitor showing NULL values because it parses ALL events (including `stats`)
- **Impact**: `stats` events don't have `alert`, `src_ip`, `dest_ip` fields → shows NULL
- **Fix**: Added filter `select(.event_type == "alert")` to only show real alerts

### 3. ⚠️ **Alerts Being Suppressed**
- **Stats showed**: `"alerts_suppressed": 18"` - Suricata was suppressing threshold alerts
- **Cause**: Test rule matching first prevented threshold tracking
- **Fix**: Removing test rules allows proper threshold counting

## How To Test Properly

### 1. Test ICMP Flood (Priority 1 - Auto-Blocks)
```bash
# In Mininet CLI:
h1 ping -c 25 -i 0.2 h3

# Expected:
# - After ~20 pings: Suricata generates ICMP Flood alert (SID 1000002, severity 1)
# - Controller sees priority 1 → blocks 10.0.1.1 on all switches
# - Remaining pings fail
```

### 2. Monitor Alerts
```bash
# In separate terminal:
./scripts/monitor.sh

# Should show:
# {
#   "time": "2026-01-26...",
#   "alert": "ICMP Flood Attack Detected",
#   "severity": 1,
#   "src": "10.0.1.1",
#   "dst": "10.0.1.3"
# }
```

### 3. Verify Blocking
```bash
# Check blocked IPs:
cat /tmp/blocked_ips.txt

# Try ping after block:
h1 ping h2  # Should FAIL

# From different host:
h3 ping h1  # Should FAIL (h1 blocked as destination)
h5 ping h2  # Should WORK
```

## Root Causes

1. **Rule Order Matters**: Specific rules (test rules) match before generic threshold rules
2. **Suricata Threshold Logic**: Once a rule matches, threshold counters for other rules don't increment
3. **Priority vs Severity**: Suricata uses "severity" field (1=high, 3=low), controller checks priority [1,2]

## Current Configuration

✅ **Fixed**:
- Test rules disabled
- Monitor script filters for alerts only
- Suricata interface correct (`suricata-eth0`)
- OVS mirror properly configured
- Controller alert thread running

✅ **Working Rules** (Priority 1):
- ICMP Flood: 20 packets in 5s
- SYN Port Scan: 20 SYN in 10s  
- SSH Brute Force: 10 attempts in 60s
- SQL Injection detection
- DNS Amplification: 50 in 10s
- SYN Flood: 30 in 2s
- UDP Flood: 50 in 2s
- TCP Connection Flood: 40 in 3s
