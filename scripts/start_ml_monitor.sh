#!/bin/bash
# Start ML Network Monitor Service

echo "Starting ML Network Monitor..."

# Get the project root directory (parent of scripts/)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo "Project root: $PROJECT_ROOT"

# Check if models exist
if [ ! -f "$PROJECT_ROOT/ml_system/models/anomaly_detector.pkl" ] || [ ! -f "$PROJECT_ROOT/ml_system/models/attack_classifier.pkl" ]; then
    echo "⚠️  ML models not found!"
    echo "   Expected location: $PROJECT_ROOT/ml_system/models/"
    echo "   Run training first: cd ml_system && python3 train_models.py"
    exit 1
fi

echo "✓ Models found"

# Check if topology is running
if ! ip link show s1-eth1 &>/dev/null; then
    echo "⚠️  Network interface 's1-eth1' not found!"
    echo "   Start the topology first: sudo ./scripts/start_topology.sh"
    exit 1
fi

# Clear old alerts
> /tmp/ml_alerts.json

# Start ML monitor in background
cd ml_system
sudo python3 ml_monitor.py s1-eth1 > ../logs/ml_monitor.log 2>&1 &
ML_PID=$!

echo "✓ ML Monitor started (PID: $ML_PID)"
echo "  Interface: s1-eth1"
echo "  Alerts: /tmp/ml_alerts.json"
echo "  Logs: logs/ml_monitor.log"
echo ""
echo "To view live alerts:"
echo "  ./scripts/monitor.sh"
echo ""
echo "To stop ML monitor:"
echo "  sudo kill $ML_PID"

# Save PID for later
echo $ML_PID > /tmp/ml_monitor.pid