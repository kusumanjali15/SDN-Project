#!/bin/bash
# Start Ryu SDN Controller
source "$(dirname "${BASH_SOURCE[0]}")/env.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Ryu SDN Controller ==="
echo "Controller will listen on port $SDN_CONTROLLER_PORT"
echo "Verbose logging enabled - you will see flows being installed"
echo ""

# Activate the Ryu virtual environment (path set by SDN_VENV in .env)
if [ -f "$SDN_VENV/bin/activate" ]; then
    source "$SDN_VENV/bin/activate"
    echo "Using Python environment: $SDN_VENV"
elif ! command -v ryu-manager >/dev/null 2>&1; then
    echo "ERROR: ryu-manager not found and no venv at SDN_VENV=$SDN_VENV"
    echo "Set SDN_VENV in .env to your Ryu virtual environment."
    exit 1
fi

# Run controller (INFO level logging - ML predictions will be visible)
ryu-manager --ofp-tcp-listen-port "$SDN_CONTROLLER_PORT" "$PROJECT_DIR/controller/ryu_controller.py"
