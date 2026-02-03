# ML Module for SDN-IDS

Machine Learning integration for the SDN-Suricata IDS project. Provides:
1. **Anomaly Detection** (Isolation Forest) - Identify abnormal network traffic patterns
2. **Attack Classification** (Random Forest) - Classify attack types: DDoS, Port Scan, Brute Force

## Architecture

```
                    ┌─────────────────────┐
                    │   Ryu Controller    │
                    │  (packet_in events) │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │    MLPredictor      │
                    │ (inference/predictor)│
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
┌─────────▼─────────┐ ┌────────▼────────┐ ┌────────▼────────┐
│ FlowCollector     │ │ AnomalyDetector │ │AttackClassifier │
│ (data/collector)  │ │ (Isolation      │ │(Random Forest   │
│                   │ │  Forest)        │ │ classification) │
└───────────────────┘ └─────────────────┘ └─────────────────┘
```

## Directory Structure

```
ml/
├── data/
│   ├── collector.py          # Flow statistics collection
│   ├── preprocessor.py       # Data normalization
│   ├── generate_dataset.py   # Synthetic dataset generator
│   └── datasets/             # Training data
├── models/
│   ├── anomaly_detector.py   # Isolation Forest
│   ├── attack_classifier.py  # Random Forest classifier
│   └── trained/              # Saved model weights
├── inference/
│   └── predictor.py          # Real-time prediction interface
├── training/
│   ├── train_anomaly.py      # Train anomaly detection
│   └── train_classifier.py   # Train attack classifier
├── tests/
│   ├── test_pipeline.py      # Pipeline tests
│   └── test_trained_models.py # Model accuracy tests
└── requirements.txt          # Python dependencies
```

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Generate Training Data (if not already done)
```bash
python data/generate_dataset.py
```

### 3. Train Models
```bash
# Train anomaly detector
python training/train_anomaly.py --data data/datasets/sdn_flows.csv

# Train attack classifier
python training/train_classifier.py --data data/datasets/sdn_flows.csv
```

### 4. Test Models
```bash
python tests/test_trained_models.py
```

## Trained Models

Located in `models/trained/`:
- **anomaly_detector.pkl** - Isolation Forest (trained on normal traffic)
- **attack_classifier.pkl** - Random Forest (4 classes: normal, ddos, portscan, bruteforce)
- **flow_preprocessor.pkl** - Feature scaler (StandardScaler)

### Model Performance
- Anomaly Detection: Detects ~16.5% of traffic as anomalies
- Attack Classification: **99.98% accuracy** on test set
  - Normal: 100% precision/recall
  - DDoS: 100% precision, 99.9% recall
  - Port Scan: 100% precision/recall
  - Brute Force: 100% precision/recall

## Integration with Ryu Controller

```python
from ml.inference.predictor import MLPredictor

# In controller __init__
self.ml_predictor = MLPredictor()
self.ml_predictor.load_models()

# In packet_in handler
def _packet_in_handler(self, ev):
    # ... existing code ...
    
    # Get ML prediction
    result = self.ml_predictor.predict_from_packet_data(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        packet_size=len(msg.data),
        tcp_flags=tcp_flags
    )
    
    if result and result.recommendation == 'block':
        self._block_ip_all_switches(src_ip, f"ML: {result.attack_type}")
```

## Attack Classes

| Class | Description | Features |
|-------|-------------|----------|
| normal | Legitimate traffic | Low packet rate, varied ports |
| ddos | DDoS/DoS attacks | High packet rate, many SYN flags |
| portscan | Port scanning | Many RST responses, short flows |
| bruteforce | Password attacks | Many connection attempts to auth ports |

## Feature Set (20 features)

| Category | Features |
|----------|----------|
| Flow Stats | duration, packet_count, byte_count |
| Rate Stats | packets_per_second, bytes_per_second |
| Packet Size | avg, min, max packet size |
| IAT | mean, std, min, max inter-arrival time |
| TCP Flags | syn, ack, fin, rst, psh counts |
| Ports | src_port, dst_port, protocol |
