# IoT-SDN Project with Suricata IDS Integration

A Software-Defined Networking (SDN) project integrating **Ryu OpenFlow Controller** with **Suricata IDS** for real-time threat detection and automated network defense. Includes **Node-RED IoT integration** via veth pairs for simulating IoT device traffic.

## Overview

This project demonstrates how SDN can be combined with network intrusion detection to create an automated security response system. Traditional networks require manual intervention when threats are detected, but this system automatically blocks malicious IP addresses within seconds of detection.

**Key Concepts:**
- **Software-Defined Networking (SDN)**: Separates the control plane (decision-making) from the data plane (packet forwarding). The Ryu controller makes all routing decisions, while OVS switches simply forward packets according to flow rules.
- **OpenFlow Protocol**: The communication standard between the controller and switches. We use OpenFlow 1.3 which supports multiple flow tables, group tables, and meter tables.
- **Intrusion Detection System (IDS)**: Suricata monitors network traffic for suspicious patterns. Unlike an IPS (Intrusion Prevention System), an IDS only detects—but our SDN controller acts on these detections to block threats.
- **Traffic Mirroring**: A copy of all traffic passing through S1 is sent to Suricata for inspection without affecting the original packet flow.

## Architecture

```
                        ┌─────────────────────┐
                        │   Ryu Controller    │
                        │  (SimpleSwitch13)   │
                        └─────────┬───────────┘
                                  │ OpenFlow 1.3 (port 6653)
    ┌─────────────────────────────┼─────────────────────────────┐
    │                             │                             │
    ▼                             ▼                             ▼
┌───────┐                     ┌───────┐                     ┌───────┐
│  S1   │◄────────────────────│  S2   │     ...             │  S5   │
│(Main) │                     │       │                     │       │
└───┬───┘                     └───┬───┘                     └───┬───┘
    │                             │                             │
    │ Port Mirror                 ├── h1 (Temp Sensor)          ├── h7 (Thermostat)
    ▼                             │   └── veth ↔ Node-RED       │   └── veth ↔ Node-RED
┌────────────┐                    └── h2 (Motion)               └── h8 (Hub)
│ Suricata   │
│   IDS      │
└─────┬──────┘
      │ EVE JSON alerts
      ▼
┌──────────────────────┐
│ /tmp/eve.json        │ ──► Controller monitors & auto-blocks
└──────────────────────┘
```

## Features

- **Traffic Mirroring**: All packets passing through S1 are duplicated and sent to Suricata via a dedicated port. This is achieved by adding an extra output action in the OpenFlow flow rules, not by OVS mirror configuration. This approach ensures the controller has full visibility into what traffic is being monitored.

- **Real-time IDS**: Suricata runs in AF_PACKET mode, capturing packets directly from the network interface with minimal overhead. It analyzes traffic against 231 custom rules designed for IoT environments, including flood detection, protocol abuse, and device-specific protections.

- **Automated Blocking**: When Suricata detects a high-severity threat (severity 1 or 2), it writes an alert to `/tmp/eve.json`. The controller's monitoring thread detects this within 500ms and immediately installs drop rules on ALL connected switches, not just the one where the attack was detected. This prevents lateral movement.

- **Node-RED Integration**: Virtual Ethernet (veth) pairs create a bridge between the host operating system and Mininet's isolated network namespace. This allows Node-RED (running on the host) to inject IoT traffic into the simulated network, enabling realistic IoT attack simulations.

- **Alert Deduplication**: Without deduplication, a single flood attack could generate hundreds of identical alerts, overwhelming the controller. The system tracks (SID, source_ip) combinations and suppresses duplicates within a 60-second window.

- **Persistence**: The system survives restarts gracefully. Blocked IPs are saved to `/tmp/blocked_ips.txt` and reloaded on startup. The alert file position is tracked in `/tmp/alert_position.txt` so already-processed alerts aren't re-processed after restart.

- **IoT-Specific Detection**: Custom Suricata rules protect against IoT-specific threats like device impersonation, unauthorized cross-VLAN communication, data exfiltration from sensors, and compromised devices participating in botnets.

## Code Structure

### Controller ([controller/ryu_controller.py](controller/ryu_controller.py))

**Class: `SimpleSwitch13`** - Learning switch with IDS integration (480 lines)

This is the brain of the system. It extends Ryu's `app_manager.RyuApp` base class and implements a learning switch (like a traditional L2 switch that learns MAC addresses) with added security capabilities.

**How the Learning Switch Works:**
1. When a packet arrives with unknown destination, it's sent to the controller (table-miss)
2. Controller records: "MAC X is reachable via port Y on switch Z"
3. Controller installs a flow rule so future packets to MAC X go directly to port Y
4. This process repeats until all MACs are learned, then traffic flows without controller involvement

**Key Methods Explained:**

| Method | Description |
|--------|-------------|
| `__init__()` | Initializes data structures (`mac_to_port` dict, `blocked_ips` set, `datapaths` dict), loads configuration files, and spawns a daemon thread for alert monitoring. The daemon thread runs independently and doesn't block the main OpenFlow event loop. |
| `_load_suricata_port()` | Reads `/tmp/suricata_port.txt` which contains the DPID and port number where Suricata is connected (e.g., "1,1" means DPID 1, port 1). Retries up to 10 times with 2-second delays since topology may not be ready immediately. |
| `_load_blocked_ips()` | Reads previously blocked IPs from disk. This ensures that if an attacker was blocked before a restart, they remain blocked after the system comes back up. |
| `_monitor_alerts()` | Runs in a background thread, continuously reading new lines from `/tmp/eve.json`. Uses file position tracking to efficiently read only new alerts without re-processing old ones. Checks for file rotation (when Suricata creates a new log file). |
| `_process_alert()` | Parses JSON alert data, extracts severity/SID/IPs. Checks deduplication cache to avoid processing the same alert repeatedly. For severity 1-2 alerts, triggers the blocking mechanism. |
| `_block_ip_all_switches()` | Iterates through all switches in `self.datapaths` and calls `_install_ip_block_rules()` on each. This ensures the attacker is blocked network-wide, not just on one switch. |
| `_install_ip_block_rules()` | Creates two OpenFlow rules per blocked IP: one matching `ipv4_src=attacker_ip` and one matching `ipv4_dst=attacker_ip`. Both rules have empty action lists, which in OpenFlow means "drop the packet". Priority 200 ensures these rules take precedence over normal forwarding rules (priority 10). |
| `switch_features_handler()` | OpenFlow event handler triggered when a switch connects. Installs the table-miss rule (priority 0, sends unmatched packets to controller) and applies any existing IP blocks to the new switch. |
| `_packet_in_handler()` | The main packet processing logic. Learns source MAC, determines output port (flood if unknown, specific port if known), adds mirror action for S1, and installs flow rules. Also checks if packet is from/to a blocked IP and drops it before processing. |

**Key Configuration:**
- Alert file: `/tmp/eve.json` - Suricata's EVE JSON output containing all alerts
- Blocked IPs file: `/tmp/blocked_ips.txt` - Persisted list of blocked IPs (survives restarts)
- Suricata port file: `/tmp/suricata_port.txt` - Written by topology, read by controller
- Alert deduplication window: 60 seconds - Same (SID, IP) won't trigger multiple blocks
- Blocking priority: 200 (overrides learning flows at priority 10, above table-miss at priority 0)

### Topology ([topology/topology.py](topology/topology.py))

**Class: `IoTSDNTopology`** - Network structure with IoT integration (287 lines)

This file uses Mininet to create a virtual network that behaves like a real physical network. Mininet uses Linux network namespaces to isolate each virtual host, and Open vSwitch (OVS) for the switches.

**Why Mininet?**
- Creates realistic network behavior without physical hardware
- Each host has its own network stack (can run real applications)
- OVS switches support full OpenFlow feature set
- Can simulate network delays, bandwidth limits, and packet loss

**Network Design:**
- **Main Switch (S1)**: The central aggregation point. All inter-switch traffic passes through S1, making it the ideal location for traffic mirroring. Suricata sees all traffic by monitoring just this one switch.
- **Access Switches (S2-S5)**: Edge switches that connect to end hosts. Each switch connects two hosts (one from each VLAN) and uplinks to S1 in a star topology.
- **Suricata Host**: Created as a Mininet host (not a real host) with IP 10.0.0.100. Its interface (`suricata-eth0`) receives mirrored traffic. **CRITICAL**: Must be the first link added to S1 to get a predictable port number (port 1).

**Understanding Veth Pairs:**

Veth (Virtual Ethernet) pairs are like a virtual network cable with two ends. When you send a packet into one end, it comes out the other. We use them to connect the host OS (where Node-RED runs) to the Mininet network namespace (where simulated IoT devices live).

```
Host OS (Node-RED)          Mininet Namespace (h1)
      │                              │
      │ veth-host-h1                 │ veth-h1
      │ (172.16.3.1/30)              │ (172.16.3.2/30)
      └──────────────────────────────┘
           Virtual Ethernet Pair
```

**Veth Pairs for Node-RED:**
| Host | Device Type | Mininet IP | Node-RED IP | Purpose |
|------|-------------|------------|-------------|---------|
| h1 | Temperature Sensor | 10.0.1.1 (+ 172.16.3.2/30) | 172.16.3.1/30 | Simulates temperature readings from IoT sensor |
| h3 | Smart Light | 10.0.1.3 (+ 172.16.4.2/30) | 172.16.4.1/30 | Simulates smart bulb control commands |
| h5 | Security Camera | 10.0.1.5 (+ 172.16.5.2/30) | 172.16.5.1/30 | Simulates video stream or motion alerts |
| h7 | Smart Thermostat | 10.0.1.7 (+ 172.16.7.2/30) | 172.16.7.1/30 | Simulates HVAC control traffic |

**Key Functions:**
| Function | Description |
|----------|-------------|
| `IoTSDNTopology.build()` | Defines the network topology declaratively. Creates 5 switches, 9 hosts (8 IoT + Suricata), and all interconnecting links. The order of `addLink()` calls matters—Suricata must be first to get port 1 on S1. |
| `add_veth_to_host()` | Creates a veth pair, configures one end on the host OS with an IP address, moves the other end into the Mininet host's network namespace using `ip link set netns`, and configures it with an IP. This is the magic that allows external traffic injection. |
| `startNetwork()` | The main entry point. Creates the Mininet network, starts it, discovers which port Suricata is on (by inspecting S1's interfaces), writes the port mapping to `/tmp/suricata_port.txt`, creates all veth pairs, displays helpful info, and starts the CLI. |

### Configuration Files

**[config/suricata.yaml](config/suricata.yaml)** - Suricata IDS configuration

Suricata is a high-performance Network IDS, IPS, and Network Security Monitoring engine. This configuration file controls how Suricata captures packets, what protocols it decodes, and where it outputs alerts.

Key settings explained:
- **Interface: `suricata-eth0`** - The network interface Suricata listens on. This is the Mininet host's interface that receives mirrored traffic from S1.
- **AF_PACKET mode** - Uses Linux's AF_PACKET socket for high-performance packet capture. More efficient than libpcap for high-volume traffic.
- **Output: `/tmp/eve.json`** - EVE (Extensible Event Format) JSON output. Each alert is a single JSON line, making it easy to parse programmatically.
- **HOME_NET: `10.0.1.0/24, 10.0.2.0/24, 172.16.0.0/16`** - Defines "internal" networks. Rules can use `$HOME_NET` to match only internal traffic.
- **Protocols** - HTTP, DNS, TLS, SSH, and MQTT are enabled for deep packet inspection. This allows rules to match on application-layer content.

**[config/custom.rules](config/custom.rules)** - Detection rules (231 lines)

Suricata rules follow a specific syntax: `action protocol source -> destination (rule options)`. The `priority` field (1-4, lower is more severe) determines whether the controller will auto-block.

| Category | SID Range | Examples | Threshold |
|----------|-----------|----------|-----------|
| Flood Detection | 1000001-1000020 | ICMP flood, TCP SYN flood, UDP flood | 20-100 packets in 10 seconds triggers alert |
| IoT Device Attacks | 2000001-2000003 | VLAN1/2 internal floods, cross-VLAN traffic | 15-20 packets in 10-30 seconds |
| Node-RED Attacks | 2000010-2000012 | Traffic from 172.16.x.x flooding Mininet | 15-50 packets in 10-30 seconds |
| IoT Protocols | 2000020-2000022 | MQTT connection floods, HTTP path traversal, brute force | Content matching + thresholds |
| Device Protection | 2000030-2000041 | Per-device rules for h1-h8, exfiltration detection | Device-specific thresholds |
| Compromised IoT | 2000050-2000051 | Outbound DDoS participation, external port scanning | 30-50 connections in 10-30 seconds |
| Testing/Monitor | 9000001-9000002 | Low-priority rules for debugging (severity 3, won't auto-block) | No threshold |

**Rule Priority Explained:**
- **Priority 1-2**: High severity, controller will automatically block the source IP
- **Priority 3-4**: Low severity, logged only—useful for monitoring normal traffic patterns

### Scripts

All scripts are located in the `scripts/` directory and should be run from the project root.

| Script | Description |
|--------|-------------|
| [start_controller.sh](scripts/start_controller.sh) | Activates the Ryu virtual environment (`/home/kali/venvs/ryu-py310`) and starts ryu-manager listening on port 6653. Must be started first—switches need a controller to connect to. |
| [start_topology.sh](scripts/start_topology.sh) | Runs the topology script with sudo (Mininet requires root). Creates the virtual network, OVS switches, and writes Suricata port mapping. Start after controller is running. |
| [start_suricata.sh](scripts/start_suricata.sh) | Starts Suricata IDS in daemon mode. Must be started last because it needs the `suricata-eth0` interface which is created by the topology. |
| [cleanup.sh](scripts/cleanup.sh) | Comprehensive cleanup: kills ryu-manager and Suricata processes, runs `mn -c` to clean Mininet, removes OVS ports, deletes temp files. Use `--full` flag to also clear the blocked IPs list for a completely fresh start. |
| [monitor.sh](scripts/monitor.sh) | Real-time alert viewer. Uses `tail -f` on `/tmp/eve.json` and pipes through `jq` for pretty-printed, colorized JSON output. Shows only alert events, filtering out flow/stats records. |
| [status.sh](scripts/status.sh) | Quick health check displaying: TAP interface status, port config file presence, Suricata process, controller process, flow rule count on S1, and whether mirroring is active. |
| [quick_status.sh](scripts/quick_status.sh) | Compact one-line status for each component. Useful for scripting or quick checks. |
| [verify_setup.sh](scripts/verify_setup.sh) | Comprehensive validation that tests connectivity, flow installation, and mirroring functionality. Run after starting all components. |
| [manage_blocked_ips.sh](scripts/manage_blocked_ips.sh) | View, add, or remove IPs from the blocked list. Useful for manually unblocking a falsely-detected IP or pre-emptively blocking known malicious IPs. |

### Node-RED Integration

**[node-red/flows.json](node-red/flows.json)** - Pre-configured Node-RED flows for IoT simulation

Node-RED is a flow-based programming tool that makes it easy to wire together IoT devices, APIs, and services. In this project, Node-RED runs on the host OS and sends traffic into the Mininet network through veth pairs, simulating real IoT devices sending sensor data or receiving commands.

**Use Cases:**
- Simulate a temperature sensor sending periodic readings
- Test how the IDS responds to abnormal traffic patterns from "IoT devices"
- Generate attack traffic (floods, scans) to test the blocking mechanism
- Create realistic IoT communication patterns for training/demo purposes

## How It Works

This section explains the complete data flow from system startup through attack detection and blocking.

### 1. Initialization Sequence (ORDER CRITICAL)

The startup order matters because of dependencies between components:

```bash
# Terminal 1: Start controller first
# WHY: OVS switches need a controller to connect to. Without it, they'll
# operate in "fail-standalone" mode and won't receive our custom flow rules.
./scripts/start_controller.sh

# Terminal 2: Start topology
# WHY: Creates the virtual network and OVS switches. Also writes the
# Suricata port mapping file that the controller needs to know where to mirror.
# The controller will detect switches connecting and install initial flows.
sudo ./scripts/start_topology.sh

# Terminal 3: Start Suricata
# WHY: Needs the suricata-eth0 interface which only exists after topology starts.
# Also needs the network to be operational to capture meaningful traffic.
./scripts/start_suricata.sh
```

### 2. Traffic Flow (Normal Operation)

Understanding how packets flow through the system:

```
Step 1: Host h1 (10.0.1.1) wants to ping h3 (10.0.1.3)
        h1 sends ICMP echo request

Step 2: Packet arrives at S2 (h1's switch)
        S2 has no flow rule for this packet → TABLE-MISS
        S2 sends packet to controller (PacketIn event)

Step 3: Controller receives PacketIn
        - Learns: "MAC 00:00:00:00:00:01 is on S2 port 1"
        - Doesn't know where h3 is → floods packet out all ports
        - Installs flow rule: (in_port=1, eth_src=h1_mac, eth_dst=h3_mac) → flood

Step 4: Packet reaches S1 (via S2→S1 link)
        S1 also has table-miss → sends to controller
        Controller installs flow with MIRROR action:
        (match) → [output:normal_port, output:suricata_port]

Step 5: Packet reaches h3, h3 sends reply
        Process repeats in reverse, controller learns h3's location

Step 6: Subsequent packets match installed flows
        Traffic flows directly switch-to-switch without controller involvement
        But S1 still mirrors a copy to Suricata
```

### 3. Threat Detection & Response

What happens when an attack is detected:

```
Step 1: Attacker (h1) launches ICMP flood
        h1 ping -f h3  (flood ping, very fast)

Step 2: Suricata sees mirrored packets
        Counts: "21 ICMP packets from 10.0.1.1 in 10 seconds"
        Matches rule SID 1000001 (threshold: 20 in 10s)
        Writes alert to /tmp/eve.json:
        {"alert":{"severity":1,"signature_id":1000001,...},"src_ip":"10.0.1.1",...}

Step 3: Controller's monitor thread detects new alert
        Reads JSON, sees severity=1 (high priority)
        Checks deduplication cache → not seen recently
        Calls _block_ip_all_switches("10.0.1.1")

Step 4: Controller installs block rules on ALL switches
        For each switch (S1-S5):
          - Install: match(ipv4_src=10.0.1.1) → DROP (priority 200)
          - Install: match(ipv4_dst=10.0.1.1) → DROP (priority 200)

Step 5: Attacker is now isolated
        - Can't send packets (src match drops them)
        - Can't receive packets (dst match drops them)
        - Blocked on all switches, can't reach any host
        - IP saved to /tmp/blocked_ips.txt

Step 6: Controller logs the action
        🚨 HIGH PRIORITY ALERT (Severity 1) - BLOCKING IP: 10.0.1.1
        🔒 IP BLOCKED: 10.0.1.1
           Reason: ICMP Flood Detected - High frequency pings
           Applied to: 5 switches
```

### 4. Alert Processing Details

Fine-grained details about how alerts are handled:

- **Deduplication**: The controller maintains `alert_history` dict with (SID, src_ip) as keys and timestamps as values. If the same combination was seen within 60 seconds, the alert is silently discarded. This prevents a single flood attack from generating hundreds of blocking attempts.

- **Already-blocked skip**: Before processing an alert, the controller checks if `src_ip in self.blocked_ips`. If already blocked, the alert is logged at DEBUG level and skipped entirely—no need to re-block.

- **Position tracking**: The controller tracks its read position in `/tmp/eve.json` using `/tmp/alert_position.txt`. On startup, it resumes from the saved position. If the file is smaller than the saved position (file rotation), it resets to 0. This prevents re-processing old alerts after a controller restart.

- **Incomplete line handling**: Since Suricata writes JSON lines atomically but the controller might read mid-write, incomplete lines are buffered and combined with the next read. Only complete JSON lines (ending with `}`) are parsed.

## Usage

### Basic Operation
```bash
# Start all components (3 terminals required)
# Each component runs in foreground and shows logs

# Terminal 1 - Controller (shows flow installations, blocking events)
./scripts/start_controller.sh

# Terminal 2 - Topology (shows Mininet CLI after startup)
sudo ./scripts/start_topology.sh

# Terminal 3 - Suricata (runs in background, but start script waits for init)
./scripts/start_suricata.sh

# Verify everything is working
./scripts/status.sh
# Expected output:
# TAP Interface: ✓
# Port Config:   ✓ (1,1)
# Suricata:      ✓ running
# Controller:    ✓ running
# S1 Flows:      ✓ 3 rules (or more)
# Mirroring:     ✓ active
```

### Testing Attack Detection
```bash
# In Mininet CLI (Terminal 2) - trigger ICMP flood detection
# The rule triggers on 20+ ICMP packets in 10 seconds
mininet> h1 ping -c 25 -i 0.2 h3

# What to expect:
# 1. First ~20 pings succeed normally
# 2. Suricata detects flood, writes alert
# 3. Controller sees alert, blocks h1's IP (10.0.1.1)
# 4. Remaining pings fail (100% packet loss)
# 5. h1 is now completely isolated from the network

# Watch alerts in real-time (separate terminal)
./scripts/monitor.sh
# You'll see JSON like:
# {
#   "time": "2026-01-29T...",
#   "severity": 1,
#   "signature": "ICMP Flood Detected - High frequency pings",
#   "src": "10.0.1.1",
#   "dst": "10.0.1.3"
# }

# Check controller logs (Terminal 1) for blocking messages
# Look for these lines:
# 🚨 HIGH PRIORITY ALERT (Severity 1) - BLOCKING IP: 10.0.1.1
# 🔒 IP BLOCKED: 10.0.1.1

# Verify h1 is blocked
mininet> h1 ping -c 3 h2
# Should show 100% packet loss

# Check blocked IPs list
cat /tmp/blocked_ips.txt
```

### Node-RED IoT Simulation
```bash
# Node-RED connects to Mininet hosts via veth pairs
# The veth network (172.16.x.x) is separate from Mininet's network (10.0.x.x)

# From host OS (not Mininet) - test veth connectivity to h1
ping -c 3 172.16.3.2
# Should succeed - you're reaching h1 through the veth pair

# Simulate a temperature sensor sending data
# (requires a simple HTTP server running on h1 in Mininet)
mininet> h1 python3 -m http.server 8080 &
# Then from host OS:
curl http://172.16.3.2:8080/

# To simulate attack traffic from Node-RED network:
# This would trigger rule SID 2000010 (ICMP from veth to Mininet)
ping -c 25 -i 0.2 172.16.3.2
```

### Cleanup
```bash
# Standard cleanup - stops all processes but preserves blocked IPs
# Use this for normal shutdown
./scripts/cleanup.sh

# Full cleanup - also clears blocked IPs for fresh start
# Use this when you want to reset everything
./scripts/cleanup.sh --full

# What cleanup does:
# 1. Kills ryu-manager process
# 2. Kills Suricata process
# 3. Runs 'mn -c' to clean Mininet (removes OVS bridges, namespaces)
# 4. Deletes temp files (/tmp/eve.json, /tmp/suricata_port.txt, etc.)
# 5. Restarts openvswitch-switch service
```

## Network Topology

The network uses a star topology with S1 as the central switch. This design ensures all inter-host traffic passes through S1, making it the ideal point for traffic mirroring.

```
                    ┌──────────────────────────────────────────┐
                    │                  S1 (DPID=1)             │
                    │            Main Switch + Mirror          │
                    │  All traffic between switches passes     │
                    │  through here → mirrored to Suricata     │
                    └───┬──────┬───────┬───────┬───────┬───────┘
                        │      │       │       │       │
                   Suricata   S2      S3      S4      S5
                  10.0.0.100   │       │       │       │
                   (IDS)      ┌┴┐     ┌┴┐     ┌┴┐     ┌┴┐
                             h1 h2   h3 h4   h5 h6   h7 h8

   Legend:
   - S1-S5: Open vSwitch instances running OpenFlow 1.3
   - h1-h8: Mininet hosts (Linux network namespaces)
   - Suricata: Special host receiving mirrored traffic
```

**VLAN Assignment:**

VLANs in this project are logical (IP-based) rather than 802.1Q tagged. Hosts are grouped by IP subnet, and Suricata rules can match on these subnets to detect cross-VLAN attacks.

| VLAN | Subnet | Hosts | Purpose |
|------|--------|-------|---------|
| VLAN1 | 10.0.1.0/24 | h1, h3, h5, h7 | IoT Sensors - These hosts have veth pairs for Node-RED connectivity. They represent devices that send data out (temperature, motion, video). |
| VLAN2 | 10.0.2.0/24 | h2, h4, h6, h8 | IoT Actuators - Internal-only devices that receive commands (locks, alarms, hubs). No external connectivity needed. |
| Veth | 172.16.x.x/30 | h1, h3, h5, h7 | Node-RED Bridge - Point-to-point links (/30 = 2 usable IPs) between host OS and Mininet for traffic injection. |

**IoT Device Mapping:**

Each host simulates a specific IoT device type. This makes the simulation more realistic and allows for device-specific Suricata rules.

| Host | IP | Device | Veth IP | Description |
|------|-----|--------|---------|-------------|
| h1 | 10.0.1.1 | Temperature Sensor | 172.16.3.2 | Sends periodic temperature readings. High-frequency polling might look like a flood. |
| h2 | 10.0.2.2 | Motion Detector | - | Event-driven, sends alerts when motion detected. Normally quiet. |
| h3 | 10.0.1.3 | Smart Light | 172.16.4.2 | Receives on/off/dim commands. Could be target of command injection. |
| h4 | 10.0.2.4 | Smart Lock | - | Security-critical. Unauthorized access attempts are high-priority alerts. |
| h5 | 10.0.1.5 | Security Camera | 172.16.5.2 | High-bandwidth video stream. Unusual destinations could indicate hijacking. |
| h6 | 10.0.2.6 | Alarm System | - | Receives arm/disarm commands. Should only communicate with hub. |
| h7 | 10.0.1.7 | Smart Thermostat | 172.16.7.2 | HVAC control. Manipulation could cause physical damage. |
| h8 | 10.0.2.8 | Smart Hub | - | Central controller for VLAN2 devices. High-value target. |

## File-Based IPC

The components communicate through files in `/tmp/`. This approach was chosen over network sockets or message queues for simplicity and because all components run on the same host.

| File | Writer | Reader | Format | Purpose |
|------|--------|--------|--------|---------|
| `/tmp/suricata_port.txt` | Topology | Controller | `dpid,port` (e.g., `1,1`) | Tells controller which port on which switch connects to Suricata. Written once at topology startup. |
| `/tmp/eve.json` | Suricata | Controller | EVE JSON (one alert per line) | Suricata appends alerts here. Controller tail-reads for new entries. Contains all event types but controller filters for `event_type=alert`. |
| `/tmp/blocked_ips.txt` | Controller | Controller | Newline-separated IPs with header comment | Persistence file for blocked IPs. Written whenever a new IP is blocked. Read on controller startup to restore previous blocks. |
| `/tmp/alert_position.txt` | Controller | Controller | Integer (file byte offset) | Tracks how far into eve.json the controller has read. Prevents re-processing alerts after restart. |

**Why /tmp/?**
- Accessible to all processes without permission issues
- Automatically cleaned on reboot (fresh start)
- Fast (usually tmpfs/RAM-backed on modern systems)
- Visible across Mininet host namespaces (they share /tmp with host)

## Requirements

**Core Dependencies:**
- **Python 3.10+** - Required for Ryu controller and topology script
- **Ryu SDN Framework** - Installed in `/home/kali/venvs/ryu-py310`. Provides OpenFlow protocol implementation and app framework.
- **Mininet** - Creates virtual network. Install with `apt install mininet`.
- **Open vSwitch (OVS)** - Software switch with OpenFlow support. Install with `apt install openvswitch-switch`.
- **Suricata IDS 7.0+** - Network intrusion detection. Install with `apt install suricata`.

**Optional:**
- **jq** - JSON processor for pretty-printing alerts in monitor.sh. Install with `apt install jq`.
- **Node-RED** - IoT flow programming tool for traffic injection simulation. Install with `npm install -g node-red`.

**Python Packages (in Ryu venv):**
```bash
source /home/kali/venvs/ryu-py310/bin/activate
pip install ryu eventlet msgpack
```

## Troubleshooting

Common issues and their solutions:

| Issue | Cause | Solution |
|-------|-------|----------|
| "No Suricata interface found" | Topology not started yet | Start topology before Suricata. The `suricata-eth0` interface only exists after Mininet creates the network. |
| Traffic not mirrored to Suricata | Wrong port mapping | Check `/tmp/suricata_port.txt` exists and contains correct dpid,port. Verify Suricata link is first `addLink()` to S1 in topology.py. Run `sudo ovs-vsctl show` to see OVS port assignments. |
| Blocks not applied to switches | Block rules not installed | Check controller logs for `✓ Installed block rules`. Verify switches are connected (look for "SWITCH CONNECTED: DPID=X" messages). Check flow rules with `sudo ovs-ofctl dump-flows s1 -O OpenFlow13`. |
| Duplicate alerts flooding logs | Deduplication not working | Verify `alert_history` dict is being populated. Check that alert timestamps are being compared correctly. Default window is 60 seconds. |
| Veth pair not working | Namespace or IP config issue | Check with `ip link show veth-host-h1` on host OS. Verify the interface is UP and has correct IP. Check Mininet side with `h1 ip addr` in Mininet CLI. |
| Controller can't read alerts | Permission or path issue | Verify `/tmp/eve.json` exists and is readable. Check Suricata is running and configured to output to `/tmp/`. Try `tail /tmp/eve.json` to see if alerts are being written. |
| Switches not connecting | Controller not running or wrong port | Ensure controller started first and is listening on 6653. Check with `netstat -tlnp | grep 6653`. Verify topology uses `RemoteController(..., port=6653)`. |
| "OFPT_ERROR" in controller logs | OpenFlow version mismatch | Ensure all switches use `protocols='OpenFlow13'` in topology and controller has `OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]`. |

## Extending the System

### Adding New Suricata Rules

Suricata rules follow this syntax:
```
action protocol src_ip src_port -> dst_ip dst_port (options)
```

To add a new rule:
1. Edit [config/custom.rules](config/custom.rules)
2. Choose appropriate SID range:
   - 1000xxx: General network attacks (floods, scans)
   - 2000xxx: IoT-specific rules
   - 9000xxx: Testing/monitoring (won't trigger blocks)
3. Set priority based on desired response:
   - Priority 1-2: Controller will auto-block the source IP
   - Priority 3-4: Alert only, no automatic action
4. Add threshold to prevent false positives:
   ```
   threshold: type both, track by_src, count 20, seconds 10;
   ```
5. Restart Suricata: `sudo pkill suricata && ./scripts/start_suricata.sh`

**Example: Block SSH brute force from IoT devices:**
```
alert ssh 10.0.0.0/8 any -> any 22 (msg:"IoT SSH Brute Force"; \
    flow:to_server; \
    threshold: type both, track by_src, count 5, seconds 60; \
    priority:1; \
    sid:2000060; rev:1; \
    classtype:attempted-admin;)
```

### Adding New IoT Devices

1. **Add host in topology:**
   ```python
   # In IoTSDNTopology.build()
   h9 = self.addHost('h9', ip='10.0.1.9/24', mac='00:00:00:00:00:09')
   self.addLink(s5, h9)  # Connect to appropriate switch
   ```

2. **If Node-RED connectivity needed, add veth mapping:**
   ```python
   # In VETH_MAP at top of file
   VETH_MAP = {
       ...
       "h9": ("172.16.9.1/30", "172.16.9.2/30"),  # New device
   }
   ```

3. **Update device name mappings for display:**
   ```python
   # In startNetwork()
   device_names = {
       ...
       'h9': 'New Sensor Type',
   }
   ```

4. **Add device-specific Suricata rules if needed** (see above)

5. **Restart topology:** `./scripts/cleanup.sh && sudo ./scripts/start_topology.sh`

### Modifying Controller Behavior

**Change which alerts trigger blocking:**
```python
# In _process_alert(), modify the severity check:
# Current: blocks severity 1-2
if severity in [1, 2] and src_ip:
# To also block severity 3:
if severity in [1, 2, 3] and src_ip:
```

**Change deduplication window:**
```python
# In __init__(), modify:
self.alert_dedup_window = 60  # Change to desired seconds
```

**Change flow priorities:**
```python
# Priority hierarchy (higher number = higher priority):
# 0   - Table-miss (send to controller)
# 10  - Learned MAC forwarding rules
# 200 - IP blocking rules (ensure blocks override learning)
```

**Add new blocking criteria (e.g., block destination instead of source):**
```python
# In _process_alert(), add:
if some_condition and dst_ip:
    self._block_ip_all_switches(dst_ip, "Custom reason")
```

## License

Open source project for educational purposes.
