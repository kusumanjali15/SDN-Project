# SDN Project with Suricata IDS Integration

A Software-Defined Networking (SDN) project integrating Ryu Controller with Suricata IDS for real-time threat detection and automated network defense.

## Architecture

```
┌─────────────┐
│   Ryu       │
│ Controller  │ ← Controls all switches via OpenFlow
└──────┬──────┘
       │ (OpenFlow protocol on port 6653)
       │
       ├─────────┬─────────┬─────────┬─────────┐
       ↓         ↓         ↓         ↓         ↓
      S1        S2        S3        S4        S5
       │
       │ (OVS Mirror - copies all traffic)
       ↓
   Suricata IDS (receives mirrored traffic via veth pair)
       │
       │ (Sends alerts via JSON)
       ↓
   Ryu Controller (blocks malicious IPs)
```

## Features

- **Traffic Mirroring**: Native OVS port mirroring on S1 to capture all network traffic
- **Real-time IDS**: Suricata analyzes mirrored traffic for threats
- **Automated Blocking**: Controller automatically blocks high-severity threats (priority 1-2)
- **VLAN Support**: Separate VLANs for network segmentation
- **Attack Detection**: Custom Suricata rules for ICMP flood detection

## Code Structure

### Controller (`controller/ryu_controller.py`)

**Main Components:**

1. **SDNController Class**: Core Ryu application with OpenFlow 1.3 support
   - `__init__()`: Initializes controller, loads blocked IPs and Suricata port configuration
   - `_load_suricata_port()`: Loads Suricata port mapping from `/tmp/suricata_port.json`
   - `_load_blocked_ips()`: Loads previously blocked IPs from `/tmp/blocked_ips.json`

2. **Alert Monitoring**:
   - `_monitor_alerts()`: Background thread monitoring `/tmp/suricata-alerts.json`
   - `_process_alert()`: Processes incoming Suricata alerts
   - Blocks IPs with severity 1-2 (high priority threats)

3. **OpenFlow Handlers**:
   - `switch_features_handler()`: Installs default flows when switch connects
   - `packet_in_handler()`: Handles incoming packets, performs MAC learning, installs flows

4. **Traffic Mirroring**:
   - Automatically mirrors all traffic from S1 to Suricata port
   - `_install_mirror_rule()`: Creates flow rules to duplicate packets to IDS

5. **Blocking Logic**:
   - `_install_block_rules()`: Installs drop rules for malicious source IPs
   - Applies blocks across all connected switches
   - Persists blocked IPs to disk

### Topology (`topology/topology.py`)

**Key Functions:**

1. **CustomTopology Class**: Defines network structure
   - 5 switches (S1-S5) in a linear topology
   - 8 hosts (h1-h8) distributed across switches
   - VLAN configuration:
     - VLAN 1 (10.0.1.x): h1, h3, h5, h7
     - VLAN 2 (10.0.2.x): h2, h4, h6, h8

2. **setup_suricata_tap()**: Creates veth pair for Suricata integration
   - Creates `suricata-int` (OVS side) and `suricata-ext` (Suricata side)
   - Configures native OVS port mirroring on S1
   - Saves Suricata port mapping to `/tmp/suricata_port.json`

3. **run()**: Starts Mininet with custom topology and OpenFlow 1.3

### Configuration Files

1. **`config/suricata.yaml`**: Suricata IDS configuration
   - AF_PACKET mode on `suricata-ext` interface
   - Outputs to `/tmp/suricata-alerts.json` and `/tmp/suricata-fast.log`
   - Custom rules from `config/custom.rules`

2. **`config/custom.rules`**: Suricata detection rules
   - **SID 1000002**: ICMP Flood Attack Detection
     - Triggers on 10+ ICMP packets in 10 seconds from same source
     - Priority 1 (high severity)

### Scripts

- **`start_controller.sh`**: Starts Ryu controller in virtual environment
- **`start_topology.sh`**: Launches Mininet topology
- **`start_suricata.sh`**: Starts Suricata IDS in daemon mode
- **`cleanup.sh`**: Cleans up all processes and interfaces
- **`monitor.sh`**: Shows real-time alerts from Suricata
- **`status.sh`**: Checks status of all components

## How It Works

1. **Initialization**:
   - Ryu controller starts and listens on port 6653
   - Mininet creates topology and connects switches to controller
   - Veth pair (`suricata-int`/`suricata-ext`) is created
   - OVS mirror configured on S1 to mirror all traffic to `suricata-int`

2. **Traffic Flow**:
   - Hosts send packets → Switch S1 → Controller learns MACs
   - Controller installs flow rules for packet forwarding
   - All traffic on S1 is mirrored to Suricata via veth pair

3. **Threat Detection**:
   - Suricata analyzes mirrored traffic against rules
   - Alerts written to `/tmp/suricata-alerts.json`
   - Controller monitors alert file in real-time

4. **Automated Response**:
   - Controller processes high-severity alerts (priority 1-2)
   - Installs drop rules for malicious source IPs on all switches
   - Logs blocking action: `ATTACK DETECTED... BLOCKING IP: x.x.x.x`

## Usage

```bash
# Start all components
./scripts/start_controller.sh  # Terminal 1
./scripts/start_topology.sh    # Terminal 2
./scripts/start_suricata.sh    # Terminal 3

# Test attack detection (in Mininet CLI)
mininet> h1 ping -c 15 h3   # Triggers flood detection after 10 pings

# Monitor alerts
./scripts/monitor.sh

# Check status
./scripts/status.sh

# Cleanup
./scripts/cleanup.sh
```

## Requirements

- Python 3.10+
- Ryu SDN Framework
- Mininet
- Open vSwitch
- Suricata IDS 8.0+

## Network Topology

- **Switches**: S1, S2, S3, S4, S5 (linear connection)
- **Hosts**: 
  - VLAN 1: h1 (10.0.1.1), h3 (10.0.1.3), h5 (10.0.1.5), h7 (10.0.1.7)
  - VLAN 2: h2 (10.0.2.2), h4 (10.0.2.4), h6 (10.0.2.6), h8 (10.0.2.8)

## License

Open source project for educational purposes.
