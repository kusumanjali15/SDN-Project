#!/bin/bash
# Start Ryu SDN Controller

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Ryu SDN Controller ==="
echo "Controller will listen on port 6653"
echo "Verbose logging enabled - you will see flows being installed"
echo ""

# Activate virtual environment
# source /home/kali/venvs/ryu-py310/bin/activate

# Run controller (INFO level logging - ML predictions will be visible)
ryu-manager --ofp-tcp-listen-port 6653 "$PROJECT_DIR/controller/ryu_controller.py"
