#!/bin/bash
# Start Mininet Topology

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== Starting Mininet Topology ==="
echo "Make sure controller is running first!"
echo ""

sudo python3 "$PROJECT_DIR/topology/topology.py"
