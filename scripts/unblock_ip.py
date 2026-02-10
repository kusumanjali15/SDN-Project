#!/usr/bin/env python3
"""
CLI tool to unblock IPs from the SDN-IDS controller.

Usage:
    python unblock_ip.py <ip_address>
    
Example:
    python unblock_ip.py 192.168.1.10
"""

import sys
import os

def unblock_ip_via_file(ip_address):
    """
    Unblock an IP by creating a command file that the controller monitors.
    This is a simple file-based IPC mechanism.
    """
    command_file = '/tmp/controller_commands.txt'
    
    try:
        with open(command_file, 'a') as f:
            f.write(f"UNBLOCK:{ip_address}\n")
        
        print(f"✅ Unblock command sent for IP: {ip_address}")
        print(f"   Command written to: {command_file}")
        print(f"   Controller will process this shortly...")
        return True
        
    except Exception as e:
        print(f"❌ Error writing command file: {e}")
        return False

def show_blocked_ips():
    """Show currently blocked IPs"""
    blocked_file = '/tmp/blocked_ips.txt'
    
    if not os.path.exists(blocked_file):
        print("ℹ️  No blocked IPs file found")
        return
    
    try:
        with open(blocked_file, 'r') as f:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if lines:
            print(f"\n📋 Currently blocked IPs ({len(lines)}):")
            for ip in lines:
                print(f"   • {ip}")
        else:
            print("ℹ️  No IPs currently blocked")
            
    except Exception as e:
        print(f"❌ Error reading blocked IPs: {e}")

def main():
    """Main CLI interface"""
    if len(sys.argv) < 2:
        print("=" * 60)
        print("SDN-IDS IP Unblock Tool")
        print("=" * 60)
        print("\nUsage:")
        print("  python unblock_ip.py <ip_address>")
        print("  python unblock_ip.py --list")
        print("\nExamples:")
        print("  python unblock_ip.py 192.168.1.10")
        print("  python unblock_ip.py --list")
        print()
        
        # Show currently blocked IPs
        show_blocked_ips()
        sys.exit(1)
    
    if sys.argv[1] == '--list':
        show_blocked_ips()
        sys.exit(0)
    
    ip_address = sys.argv[1]
    
    # Basic IP validation
    parts = ip_address.split('.')
    if len(parts) != 4:
        print(f"❌ Invalid IP address format: {ip_address}")
        sys.exit(1)
    
    try:
        for part in parts:
            num = int(part)
            if num < 0 or num > 255:
                raise ValueError()
    except ValueError:
        print(f"❌ Invalid IP address: {ip_address}")
        sys.exit(1)
    
    print("=" * 60)
    print("SDN-IDS IP Unblock Tool")
    print("=" * 60)
    print(f"\n🔓 Unblocking IP: {ip_address}\n")
    
    if unblock_ip_via_file(ip_address):
        print("\n✅ Command sent successfully!")
        print("   Check controller logs to confirm unblock:")
        print("   tail -f /var/log/ryu/controller.log")
        print()
    else:
        print("\n❌ Failed to send unblock command")
        sys.exit(1)

if __name__ == '__main__':
    main()
