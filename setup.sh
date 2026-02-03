#!/bin/bash
# Simple Setup Script for ML-Enhanced SDN-IDS

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║     ML-Enhanced SDN-IDS Setup Script                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Step 1: Check Python version
echo "📋 Step 1: Checking Python version..."
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "   Python version: $PYTHON_VERSION"

if python3 -c "import sys; exit(0 if sys.version_info >= (3,8) else 1)"; then
    echo -e "   ${GREEN}✓ Python 3.8+ detected${NC}"
else
    echo -e "   ${RED}✗ Python 3.8+ required!${NC}"
    exit 1
fi
echo ""

# Step 2: Install Python packages
echo "📦 Step 2: Installing Python ML packages..."
echo "   This may take a few minutes..."

pip3 install scikit-learn numpy scapy --break-system-packages --quiet

if [ $? -eq 0 ]; then
    echo -e "   ${GREEN}✓ Packages installed successfully${NC}"
else
    echo -e "   ${YELLOW}⚠️  Installation had warnings, trying alternative method...${NC}"
    python3 -m pip install --user scikit-learn numpy scapy --quiet
fi

# Verify installation
python3 << EOF
try:
    import sklearn
    import numpy
    import scapy
    print("   ✓ All packages verified")
except ImportError as e:
    print(f"   ✗ Package verification failed: {e}")
    exit(1)
EOF

if [ $? -ne 0 ]; then
    echo -e "   ${RED}✗ Package installation failed!${NC}"
    exit 1
fi
echo ""

# Step 3: Create directories
echo "📁 Step 3: Creating directories..."
mkdir -p ml_system/models training_data logs
chmod +x scripts/*.sh ml_system/*.py
echo -e "   ${GREEN}✓ Directories created${NC}"
echo ""

# Step 4: Train ML models
echo "🤖 Step 4: Training ML models..."
echo "   This will take 1-2 minutes..."
cd ml_system
python3 train_models.py > ../logs/training.log 2>&1

if [ -f "../ml_system/models/anomaly_detector.pkl" ] && [ -f "../ml_system/models/attack_classifier.pkl" ]; then
    echo -e "   ${GREEN}✓ ML models trained successfully!${NC}"
    # Display training report
    if [ -f "../ml_system/models/training_report.json" ]; then
        python3 << EOF
import json
with open('../ml_system/models/training_report.json', 'r') as f:
    report = json.load(f)
    print(f"   Anomaly Detector Accuracy: {report['anomaly_detector_accuracy']*100:.2f}%")
    print(f"   Attack Classifier Accuracy: {report['attack_classifier_accuracy']*100:.2f}%")
EOF
    fi
else
    echo -e "   ${RED}✗ Model training failed!${NC}"
    echo "   Check logs/training.log for details"
    exit 1
fi
cd ..
echo ""

# Step 5: Verify existing system components
echo "🔍 Step 5: Verifying system components..."

# Check for Ryu
if python3 -c "import ryu" 2>/dev/null; then
    echo -e "   ${GREEN}✓ Ryu controller available${NC}"
else
    echo -e "   ${YELLOW}⚠️  Ryu controller not found${NC}"
    echo "      Install: pip3 install ryu"
fi

# Check for Mininet
if command -v mn &> /dev/null; then
    echo -e "   ${GREEN}✓ Mininet available${NC}"
else
    echo -e "   ${YELLOW}⚠️  Mininet not found${NC}"
    echo "      Install: sudo apt install mininet"
fi

# Check for Suricata
if command -v suricata &> /dev/null; then
    echo -e "   ${GREEN}✓ Suricata IDS available${NC}"
else
    echo -e "   ${YELLOW}⚠️  Suricata not found${NC}"
    echo "      Install: sudo apt install suricata"
fi

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║                    ✓ SETUP COMPLETE!                          ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "📚 Next Steps:"
echo ""
echo "1. Read the guide:"
echo "   cat README_ML.md"
echo ""
echo "2. Start the system (4 terminals needed):"
echo "   Terminal 1: ./scripts/start_controller.sh"
echo "   Terminal 2: sudo ./scripts/start_topology.sh"
echo "   Terminal 3: ./scripts/start_suricata.sh"
echo "   Terminal 4: ./scripts/start_ml_monitor.sh"
echo ""
echo "3. View alerts:"
echo "   Terminal 5: ./scripts/monitor.sh"
echo ""
echo "4. Test attacks from Mininet CLI:"
echo "   mininet> h1 ping -c 25 -i 0.1 h3"
echo ""
echo "For detailed instructions, see README_ML.md"
echo ""
