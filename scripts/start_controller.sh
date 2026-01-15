#!/bin/bash
# Start Ryu SDN Controller

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Ryu SDN Controller ==="

# Activate virtual environment
source /home/kali/venvs/ryu-py310/bin/activate

ryu-manager --ofp-tcp-listen-port 6653 "$PROJECT_DIR/controller/ryu_controller.py"
