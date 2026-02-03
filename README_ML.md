# SDN-IDS with Machine Learning Integration

Complete Software-Defined Networking Intrusion Detection System with ML-based anomaly detection and attack classification.

## 🎯 Features

### Dual Detection System
- **🤖 ML-Based Detection**: Real-time anomaly detection and attack classification
- **🛡️ Suricata IDS**: Traditional signature-based intrusion detection
- **🔄 Unified Monitoring**: Combined alert display in monitor.sh

### ML Capabilities
- **Anomaly Detection**: Identifies NORMAL vs ANOMALY traffic dynamically
- **Attack Classification**: Labels attacks as:
  - ICMP Flood
  - SYN Flood
  - UDP Flood
  - Port Scan
  - Normal Traffic

### Automated Response
- Automatic IP blocking based on threat scores
- Real-time traffic analysis
- SDN controller integration

---

## 📋 Requirements

- **OS**: Kali Linux (or any Debian-based Linux)
- **Python**: 3.8+
- **Network**: Mininet, Open vSwitch
- **Tools**: Ryu SDN Controller, Suricata IDS

---

## 🚀 Quick Start Guide

### 1. Install Dependencies

```bash
# Install Python ML libraries
pip3 install scikit-learn numpy scapy --break-system-packages

# OR if you have issues:
python3 -m pip install --user scikit-learn numpy scapy
```

### 2. Train ML Models

```bash
cd ml_system
python3 train_models.py
```

You should see output like:
```
Generating synthetic training data...
Training Anomaly Detector...
  Accuracy: 98.50%
Training Attack Classifier...
  Accuracy: 96.25%
✓ TRAINING COMPLETE!
```

This creates:
- `models/anomaly_detector.pkl` - Binary classifier (Normal/Anomaly)
- `models/attack_classifier.pkl` - Multi-class classifier (Attack types)
- `training_data/training_dataset.json` - Training data

### 3. Start the System

Open **4 separate terminals**:

#### Terminal 1: Start Ryu Controller
```bash
./scripts/start_controller.sh
```

#### Terminal 2: Start Mininet Topology
```bash
sudo ./scripts/start_topology.sh
```

Wait for Mininet prompt: `mininet>`

#### Terminal 3: Start Suricata IDS
```bash
./scripts/start_suricata.sh
```

#### Terminal 4: Start ML Monitor
```bash
./scripts/start_ml_monitor.sh
```

### 4. View Alerts

Open **Terminal 5**:
```bash
./scripts/monitor.sh
```

This displays both ML and Suricata alerts in real-time!

---

## 🧪 Testing the System

### From Mininet CLI (Terminal 2)

#### Test 1: ICMP Flood
```bash
mininet> h1 ping -c 25 -i 0.1 h3
```
Expected: ML detects ICMP_FLOOD, blocks h1 (10.0.1.1)

#### Test 2: Multi-Source Attack
```bash
mininet> h1 ping -c 30 -i 0.1 h3 &
mininet> h5 ping -c 30 -i 0.1 h3 &
mininet> h7 ping -c 30 -i 0.1 h3 &
```
Expected: ML blocks all three attackers

#### Test 3: SYN Flood (requires hping3)
```bash
mininet> h1 cmd hping3 -S -p 80 -c 40 --faster 10.0.1.3
```

#### Test 4: UDP Flood (requires hping3)
```bash
mininet> h1 cmd hping3 --udp -p 53 -c 60 --faster 10.0.1.3
```

#### Test 5: Port Scan (requires nmap)
```bash
mininet> h1 cmd nmap -sS -p 1-100 10.0.1.3
```

### What You'll See in monitor.sh

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🤖 ML DETECTION ALERT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Time:        2026-02-02T19:30:45
Source IP:   10.0.1.1
Dest IP:     10.0.1.3
Attack:      ICMP_FLOOD
Confidence:  95.3%
Threat:      87/100
Protocol:    ICMP
Action:      ⛔ BLOCKED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🛡️  SURICATA IDS ALERT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Time:        2026-02-02T19:30:46
Signature:   ICMP Flood Detected
Severity:    1
SID:         1000002
Source:      10.0.1.1:8
Dest:        10.0.1.3:0
Protocol:    ICMP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## 📂 Project Structure

```
SDN-ML-Project/
├── ml_system/                    # ML Detection System
│   ├── ml_detector.py           # Core ML engine
│   ├── ml_monitor.py            # Network monitoring service
│   └── train_models.py          # Model training script
│
├── models/                       # Trained ML models
│   ├── anomaly_detector.pkl     # Anomaly detection model
│   ├── attack_classifier.pkl    # Attack classification model
│   └── training_report.json     # Training metrics
│
├── training_data/                # Training datasets
│   └── training_dataset.json    # Synthetic training data
│
├── controller/                   # SDN Controller
│   └── ryu_controller.py        # Ryu OpenFlow controller
│
├── topology/                     # Network Topology
│   └── topology.py              # Mininet topology definition
│
├── scripts/                      # Control Scripts
│   ├── monitor.sh               # 🌟 Enhanced alert monitor
│   ├── start_ml_monitor.sh      # Start ML monitoring
│   ├── start_controller.sh      # Start Ryu
│   ├── start_topology.sh        # Start Mininet
│   ├── start_suricata.sh        # Start Suricata
│   └── cleanup.sh               # Cleanup resources
│
├── config/                       # Configuration
│   ├── suricata.yaml            # Suricata config
│   └── custom.rules             # Custom IDS rules
│
└── logs/                         # Log files
    └── ml_monitor.log           # ML monitor logs
```

---

## 🔍 How ML Detection Works

### Feature Extraction (12 Features)

For each source IP, the system tracks:

1. **Packets per second** - Traffic rate
2. **TCP ratio** - Percentage of TCP packets
3. **UDP ratio** - Percentage of UDP packets
4. **ICMP ratio** - Percentage of ICMP packets
5. **Port diversity** - Number of unique ports accessed
6. **Average packet size** - Mean packet size in bytes
7. **Packet size std dev** - Variation in packet sizes
8. **Average inter-arrival time** - Time between packets
9. **SYN count** - Number of SYN flags (SYN flood indicator)
10. **ACK count** - Number of ACK flags
11. **FIN count** - Number of FIN flags
12. **Total packets** - Total packets in time window

### Two-Stage Detection

**Stage 1: Anomaly Detection (Random Forest)**
- Binary classification: NORMAL vs ANOMALY
- If ANOMALY detected → proceed to Stage 2

**Stage 2: Attack Classification (Random Forest)**
- Multi-class classification
- Labels: NORMAL, ICMP_FLOOD, SYN_FLOOD, UDP_FLOOD, PORT_SCAN

### Threat Scoring

- Base score from ML confidence (0-100)
- Severity multipliers:
  - SYN Flood: 1.5x
  - UDP Flood: 1.4x
  - Port Scan: 1.3x
  - ICMP Flood: 1.2x
- Historical component (repeat offenders get higher scores)
- **Blocking threshold**: Threat score ≥ 70

---

## 🛠️ Troubleshooting

### Issue: Models not found
```bash
cd ml_system
python3 train_models.py
```

### Issue: Permission denied for ML monitor
```bash
sudo ./scripts/start_ml_monitor.sh
```

### Issue: Interface s1-eth1 not found
Start topology first:
```bash
sudo ./scripts/start_topology.sh
```

### Issue: No alerts appearing
Check if services are running:
```bash
# Check Ryu controller
ps aux | grep ryu

# Check Suricata
ps aux | grep suricata

# Check ML monitor
ps aux | grep ml_monitor

# Check alert files
ls -lh /tmp/ml_alerts.json /tmp/eve.json
```

### Issue: Import errors
```bash
# Install missing packages
pip3 install scikit-learn numpy scapy --break-system-packages

# Verify installation
python3 -c "import sklearn, numpy, scapy; print('All packages installed!')"
```

### View detailed logs
```bash
# ML monitor logs
tail -f logs/ml_monitor.log

# Suricata logs
tail -f /var/log/suricata/suricata.log

# Controller logs
tail -f /tmp/controller_output.log
```

---

## 📊 Monitoring Commands

### View blocked IPs
```bash
cat /tmp/blocked_ips.txt
```

### Clear blocked IPs
```bash
sudo rm /tmp/blocked_ips.txt
```

### ML statistics
```bash
python3 << EOF
from ml_system.ml_detector import MLNetworkDetector
detector = MLNetworkDetector()
print(detector.get_statistics())
EOF
```

### Check ML alerts
```bash
cat /tmp/ml_alerts.json | jq
```

### Real-time packet capture
```bash
sudo tcpdump -i s1-eth1 -n
```

---

## 🔄 Restarting the System

```bash
# Full cleanup
sudo ./scripts/cleanup.sh

# Restart all components
./scripts/start_controller.sh          # Terminal 1
sudo ./scripts/start_topology.sh       # Terminal 2
./scripts/start_suricata.sh            # Terminal 3
./scripts/start_ml_monitor.sh          # Terminal 4
./scripts/monitor.sh                   # Terminal 5
```

---

## 🎓 Network Topology

```
        [Ryu Controller]
               |
           [Switch S1] ← Suricata IDS (mirror port)
          /    |    \
        S2    S3    S4    S5
        |     |     |     |
       h1-h2 h3-h4 h5-h6 h7-h8
```

**Traffic Pairs**: h1↔h3, h2↔h4, h5↔h7, h6↔h8 (odd-even pairing)

**IP Addresses**:
- h1: 10.0.1.1
- h2: 10.0.2.2
- h3: 10.0.1.3
- h4: 10.0.2.4
- h5: 10.0.1.5
- h6: 10.0.2.6
- h7: 10.0.1.7
- h8: 10.0.2.8
- Suricata: 10.0.0.100

---

## 📝 ML Model Details

### Training Data Distribution
- Normal traffic: 1000 samples (56%)
- ICMP Flood: 200 samples (11%)
- SYN Flood: 200 samples (11%)
- UDP Flood: 200 samples (11%)
- Port Scan: 200 samples (11%)

### Model Architectures
- **Anomaly Detector**: Random Forest (100 trees, max_depth=10)
- **Attack Classifier**: Random Forest (150 trees, max_depth=15)

### Expected Performance
- Anomaly Detection: ~98% accuracy
- Attack Classification: ~96% accuracy

---

## 🤝 Support

For issues or questions:
1. Check the troubleshooting section above
2. View logs in `logs/` directory
3. Check alert files: `/tmp/ml_alerts.json` and `/tmp/eve.json`

---

## 📜 License

This is an educational project for SDN and ML integration demonstration.

---

**Enjoy your ML-powered SDN-IDS! 🚀**
