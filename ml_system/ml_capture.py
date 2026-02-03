#!/usr/bin/env python3
"""
ML Packet Analyzer using tcpdump as capture backend
"""

import subprocess
import re
import sys
import os
from ml_detector import MLNetworkDetector
import json
import time
from datetime import datetime

# Initialize ML detector
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
models_path = os.path.join(project_root, '/ml_systems/models')

detector = MLNetworkDetector(models_dir=models_path)
print(f"Models loaded: {detector.anomaly_model is not None}")

# Alert file
alert_file = '/tmp/ml_alerts.json'
blocked_ips_file = '/tmp/blocked_ips.txt'
blocked_ips = set()

# Stats
stats = {'packets': 0, 'anomalies': 0}

def parse_tcpdump_line(line):
    """Parse tcpdump output line"""
    # Example: "10.0.1.1 > 10.0.1.3: ICMP echo request"
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+).*?(ICMP|TCP|UDP)', line)
    if match:
        src_ip = match.group(1)
        dst_ip = match.group(2)
        protocol = match.group(3)
        
        # Get packet size
        size_match = re.search(r'length (\d+)', line)
        size = int(size_match.group(1)) if size_match else 64
        
        return {
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'size': size
        }
    return None

def analyze_packet(src_ip, dst_ip, protocol, size):
    """Analyze packet with ML"""
    global stats
    
    if src_ip in blocked_ips:
        return
    
    packet_info = {
        'protocol': protocol,
        'size': size,
        'port': 80 if protocol == 'TCP' else None,
        'timestamp': time.time(),
        'flags': ['SYN'] if protocol == 'TCP' else []
    }
    
    result = detector.analyze_packet(src_ip, packet_info)
    stats['packets'] += 1
    
    if result['is_anomaly']:
        stats['anomalies'] += 1
        
        alert = {
            'timestamp': result['timestamp'],
            'event_type': 'ml_alert',
            'src_ip': src_ip,
            'dest_ip': dst_ip,
            'attack_type': result['attack_type'],
            'confidence': result['confidence'],
            'threat_score': result['threat_score'],
            'should_block': result['should_block'],
            'reason': result['reason'],
            'protocol': protocol,
            'packet_size': size
        }
        
        # Write alert
        with open(alert_file, 'a') as f:
            json.dump(alert, f)
            f.write('\n')
        
        # Print alert
        print(f"\n{'='*60}")
        print(f"🚨 ML ALERT - {result['attack_type']}")
        print(f"{'='*60}")
        print(f"Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Source IP:  {src_ip}")
        print(f"Dest IP:    {dst_ip}")
        print(f"Confidence: {result['confidence']:.1f}%")
        print(f"Threat:     {result['threat_score']}/100")
        print(f"Protocol:   {protocol}")
        
        if result['should_block']:
            blocked_ips.add(src_ip)
            with open(blocked_ips_file, 'a') as f:
                f.write(f"{src_ip}  # ML: {result['reason']}\n")
            print(f"Action:     ⛔ IP BLOCKED")
        else:
            print(f"Action:     ⚠️  Warning")
        
        print('='*60 + '\n')

print("🔍 Starting ML Network Monitor (tcpdump backend)")
print("Monitoring all traffic...")
print("Press Ctrl+C to stop\n")

# Start tcpdump and pipe to Python
cmd = ['sudo', 'tcpdump', '-i', 'any', '-n', '-l', '2>/dev/null']
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)

try:
    for line in proc.stdout:
        parsed = parse_tcpdump_line(line)
        if parsed:
            analyze_packet(
                parsed['src_ip'],
                parsed['dst_ip'],
                parsed['protocol'],
                parsed['size']
            )
except KeyboardInterrupt:
    print(f"\n\nStopping... Analyzed {stats['packets']} packets, detected {stats['anomalies']} anomalies")
    proc.kill()
