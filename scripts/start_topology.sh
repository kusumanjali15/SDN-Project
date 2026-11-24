#!/bin/bash
# Start Mininet Topology
#
#   ./scripts/start_topology.sh            # 8 hosts (default)
#   ./scripts/start_topology.sh 32         # 32 hosts (scalability sweep)
#   SDN_HOSTS_PER_SWITCH=8 ./scripts/start_topology.sh   # same as 32
#
# Total hosts must be a multiple of 4 (they are spread over 4 access switches).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

if [ -n "$1" ]; then
    if ! [[ "$1" =~ ^[0-9]+$ ]] || [ $(( $1 % 4 )) -ne 0 ] || [ "$1" -lt 8 ]; then
        echo "Usage: $0 [total_hosts]   (multiple of 4, at least 8)"; exit 1
    fi
    SDN_HOSTS_PER_SWITCH=$(( $1 / 4 ))
fi

echo "=== Starting Mininet Topology ==="
echo "Make sure controller is running first!"
echo ""

# sudo drops environment variables, so pass the size through explicitly
sudo SDN_HOSTS_PER_SWITCH="${SDN_HOSTS_PER_SWITCH:-}" python3 "$PROJECT_DIR/topology/topology.py"
