# SDN-Suricata IDS Integration Project

## Architecture Overview

This is a Software-Defined Networking (SDN) project integrating **Ryu OpenFlow Controller** with **Suricata IDS** for automated threat detection and response. The system uses **native OVS port mirroring** to copy all traffic to Suricata, which generates alerts that trigger automatic IP blocking via OpenFlow rules.

**Critical Data Flow:**
1. Hosts → S1 (main switch) → traffic mirrored to Suricata via dedicated port
2. Suricata → `/tmp/suricata-alerts.json` (JSON alerts)
3. Ryu Controller → reads alerts → installs drop rules for malicious IPs (priority 1-2 only)
4. Blocked IPs persisted to `/tmp/blocked_ips.txt` and enforced across all switches

## Key Components

### Controller ([ryu_controller.py](controller/ryu_controller.py))
- **Class**: `SimpleSwitch13` - Learning switch with IDS integration (OpenFlow 1.3)
- **Port Discovery**: Reads `/tmp/suricata_port.txt` (format: `dpid,port`) written by topology on startup
- **Blocking Logic**: Empty actions list = drop packets (OpenFlow behavior)
- **IP Blocking**: Installed at priority 100, blocks both src and dst, persists to file
- **Traffic Mirroring**: ONLY on S1 (dpid=1) via additional OFPActionOutput to Suricata port
- **Alert Processing**: Background thread monitoring `/tmp/suricata-alerts.json` (not yet implemented - manual blocking via `block_ip()`)

### Topology ([topology.py](topology/topology.py))
- **Structure**: 5 switches (S1-S5), 8 hosts, 2 VLANs
  - VLAN1 (10.0.1.x): h1, h3, h5, h7
  - VLAN2 (10.0.2.x): h2, h4, h6, h8
- **Critical**: Suricata link MUST be first link to S1 to get predictable port number
- **Port Discovery**: Uses Mininet link API to find Suricata port, writes to `/tmp/suricata_port.txt`

### Configuration
- [config/suricata.yaml](config/suricata.yaml): AF_PACKET mode, outputs to `/tmp/suricata-alerts.json`
- [config/custom.rules](config/custom.rules): Priority 1-2 alerts trigger blocking (ICMP flood SID 1000002, SYN scan, SSH brute force, SQL injection, etc.)

## Development Workflows

### Startup Sequence (ORDER CRITICAL)
```bash
# 1. Start controller first (listens on port 6653)
./scripts/start_controller.sh

# 2. Start topology (requires controller running, creates Suricata port mapping)
sudo ./scripts/start_topology.sh

# 3. Start Suricata (requires topology running to create interfaces)
./scripts/start_suricata.sh
```

### Testing Attack Detection
```bash
# From Mininet CLI:
h1 ping -c 15 h2  # Triggers ICMP flood (SID 1000002, threshold: 10 in 10s)

# Monitor alerts:
./scripts/monitor.sh  # Tail with jq parsing

# Check controller logs for blocking (manual intervention currently needed)
```

### Cleanup
```bash
./scripts/cleanup.sh  # Kills all processes, removes veth pairs, cleans temp files
```

## Project-Specific Patterns

### OpenFlow Flow Installation
- **Priority levels**: 0 (table-miss) < 1 (MAC learning) < 100 (IP blocking)
- **Mirror pattern**: Append Suricata port to actions list AFTER normal output action
- **Drop pattern**: Empty actions list `[]` instead of DROP action

### File-Based IPC
- `/tmp/suricata_port.txt`: Topology → Controller (dpid,port format)
- `/tmp/blocked_ips.txt`: Controller persistence (newline-separated IPs)
- `/tmp/suricata-alerts.json`: Suricata → Controller (EVE JSON format)

### Virtual Environment
- Ryu runs in `/home/kali/venvs/ryu-py310` (Python 3.10, activated in [start_controller.sh](scripts/start_controller.sh))
- Project has `.venv` for development tools (activated in terminal)

### Mininet Integration
- Use `RemoteController` pointing to 127.0.0.1:6653
- Must set `protocols='OpenFlow13'` on all switches
- Suricata connected as Mininet host with IP 10.0.0.100

## Common Issues

**"No Suricata interface found"**: Start topology before Suricata (creates veth pair)
**Traffic not mirrored**: Check S1 port assignment with `sudo ovs-vsctl show` and `/tmp/suricata_port.txt`
**Blocks not applied**: Ensure `_install_block_rules()` called in `switch_features_handler()`
**Alert not triggering**: Verify Suricata rules have priority 1-2 and check `/tmp/suricata-alerts.json`

## Extending the System

### Adding New Suricata Rules
1. Add to [config/custom.rules](config/custom.rules) with priority 1-2 for auto-blocking
2. Assign unique SID (1000xxx range)
3. Restart Suricata: `sudo pkill suricata && ./scripts/start_suricata.sh`

### Modifying Topology
- Update [topology/topology.py](topology/topology.py) `build()` method
- Keep Suricata link as first link to S1 for consistent port numbering
- VLANs are logical (IP-based) not 802.1Q tagged

### Controller Extensions
- Add new event handlers with `@set_ev_cls` decorator
- Use `self.mac_to_port[dpid]` for MAC learning state
- Check `dpid in self.suricata_port` before mirroring operations
