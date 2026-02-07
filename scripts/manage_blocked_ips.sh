#!/bin/bash

# Script to manage blocked IPs for Ryu Controller
BLOCKED_IPS_FILE="/tmp/blocked_ips.txt"

# Function to display usage
usage() {
    echo "Usage: $0 {add|remove|list|clear} [IP_ADDRESS]"
    echo ""
    echo "Commands:"
    echo "  add <IP>     - Add an IP address to the blocked list"
    echo "  remove <IP>  - Remove an IP address from the blocked list"
    echo "  list         - List all currently blocked IPs"
    echo "  clear        - Clear all blocked IPs"
    echo ""
    echo "Examples:"
    echo "  $0 add 10.0.0.5"
    echo "  $0 remove 10.0.0.5"
    echo "  $0 list"
    exit 1
}

# Function to add IP
add_ip() {
    local ip=$1
    if [ -z "$ip" ]; then
        echo "Error: IP address required"
        usage
    fi
    
    # Create file if it doesn't exist
    touch "$BLOCKED_IPS_FILE"
    
    # Check if IP already exists
    if grep -qx "$ip" "$BLOCKED_IPS_FILE" 2>/dev/null; then
        echo "IP $ip is already in the blocked list"
    else
        echo "$ip" >> "$BLOCKED_IPS_FILE"
        echo "Added $ip to blocked list"
        echo "Note: Restart the Ryu controller for changes to take effect"
    fi
}

# Function to remove IP
remove_ip() {
    local ip=$1
    if [ -z "$ip" ]; then
        echo "Error: IP address required"
        usage
    fi
    
    if [ ! -f "$BLOCKED_IPS_FILE" ]; then
        echo "No blocked IPs file found"
        exit 1
    fi
    
    # Remove the IP from the file
    if grep -qx "$ip" "$BLOCKED_IPS_FILE"; then
        sed -i "/^${ip}$/d" "$BLOCKED_IPS_FILE"
        echo "Removed $ip from blocked list"
        echo "Note: Restart the Ryu controller for changes to take effect"
    else
        echo "IP $ip not found in blocked list"
    fi
}

# Function to list IPs
list_ips() {
    if [ ! -f "$BLOCKED_IPS_FILE" ]; then
        echo "No blocked IPs configured"
        exit 0
    fi
    
    if [ ! -s "$BLOCKED_IPS_FILE" ]; then
        echo "No blocked IPs configured"
    else
        echo "Currently blocked IPs:"
        echo "====================="
        cat "$BLOCKED_IPS_FILE"
        echo "====================="
        echo "Total: $(wc -l < "$BLOCKED_IPS_FILE") IPs blocked"
    fi
}

# Function to clear all IPs
clear_ips() {
    if [ -f "$BLOCKED_IPS_FILE" ]; then
        rm "$BLOCKED_IPS_FILE"
        echo "Cleared all blocked IPs"
        echo "Note: Restart the Ryu controller for changes to take effect"
    else
        echo "No blocked IPs file found"
    fi
}

# Main logic
case "$1" in
    add)
        add_ip "$2"
        ;;
    remove)
        remove_ip "$2"
        ;;
    list)
        list_ips
        ;;
    clear)
        clear_ips
        ;;
    *)
        usage
        ;;
esac
