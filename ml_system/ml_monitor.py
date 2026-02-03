#!/usr/bin/env python3
"""
ML Network Monitor Service
Continuously monitors network traffic and performs ML-based detection
Integrates with Ryu controller and logs to monitoring system
"""

import sys
import os
import json
import time
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import defaultdict
import threading
import signal

# Add ml_system to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ml_detector import MLNetworkDetector

class MLNetworkMonitor:
    """Real-time network monitor with ML detection"""
    
    def __init__(self, interface='s1-eth1', alert_file='/tmp/ml_alerts.json',
                 blocked_ips_file='/tmp/blocked_ips.txt'):
        """
        Initialize ML monitor
        
        Args:
            interface: Network interface to monitor
            alert_file: Where to write ML alerts
            blocked_ips_file: File to read/write blocked IPs
        """
        self.interface = interface
        self.alert_file = alert_file
        self.blocked_ips_file = blocked_ips_file
        
        # Initialize ML detector - Fix path to models
        script_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(script_dir)
        models_path = os.path.join(project_root, 'ml_system/models')
        print(f"   Script dir: {script_dir}")
        print(f"   Project root: {project_root}")
        print(f"   Looking for models in: {models_path}")
        
        # Verify models exist
        anomaly_model = os.path.join(models_path, 'anomaly_detector.pkl')
        classifier_model = os.path.join(models_path, 'attack_classifier.pkl')
        print(f"   Anomaly model exists: {os.path.exists(anomaly_model)}")
        print(f"   Classifier model exists: {os.path.exists(classifier_model)}")
        
        self.detector = MLNetworkDetector(models_dir=models_path)
        
        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'anomalies_detected': 0,
            'attacks_detected': defaultdict(int),
            'ips_blocked': 0,
            'start_time': time.time()
        }
        
        # Blocked IPs cache
        self.blocked_ips = set()
        self._load_blocked_ips()
        
        # Alert rate limiting (prevent spam)
        self.last_alert_time = defaultdict(float)
        self.alert_cooldown = 5  # seconds
        
        # Running flag
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        print("🤖 ML Network Monitor initialized")
        print(f"   Interface: {self.interface}")
        print(f"   Alert file: {self.alert_file}")
        print(f"   Models loaded: {self.detector.anomaly_model is not None and self.detector.classifier_model is not None}")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        print("\n\n🛑 Shutting down ML Monitor...")
        self.running = False
        self._print_final_stats()
        sys.exit(0)
    
    def _load_blocked_ips(self):
        """Load currently blocked IPs"""
        try:
            if os.path.exists(self.blocked_ips_file):
                with open(self.blocked_ips_file, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            self.blocked_ips.add(ip)
                print(f"   Loaded {len(self.blocked_ips)} blocked IPs")
        except Exception as e:
            print(f"   Warning: Could not load blocked IPs: {e}")
    
    def _block_ip(self, ip_address, reason):
        """Add IP to blocked list"""
        if ip_address not in self.blocked_ips:
            self.blocked_ips.add(ip_address)
            try:
                with open(self.blocked_ips_file, 'a') as f:
                    f.write(f"{ip_address}  # ML: {reason}\n")
                self.stats['ips_blocked'] += 1
                print(f"🚫 BLOCKED IP: {ip_address} - {reason}")
            except Exception as e:
                print(f"   Error blocking IP: {e}")
    
    def _write_alert(self, alert_data):
        """Write ML alert to JSON file"""
        try:
            with open(self.alert_file, 'a') as f:
                json.dump(alert_data, f)
                f.write('\n')
        except Exception as e:
            print(f"   Error writing alert: {e}")
    
    def _should_alert(self, src_ip):
        """Check if we should alert for this IP (rate limiting)"""
        current_time = time.time()
        last_time = self.last_alert_time.get(src_ip, 0)
        
        if current_time - last_time > self.alert_cooldown:
            self.last_alert_time[src_ip] = current_time
            return True
        return False
    
    def packet_callback(self, packet):
        """Process each captured packet"""
        try:
            if not packet.haslayer(IP):
                return
            
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Skip if source IP is already blocked
            if src_ip in self.blocked_ips:
                return
            
            # Extract packet information
            packet_info = {
                'size': len(packet),
                'timestamp': time.time()
            }
            
            # Determine protocol and extract details
            if packet.haslayer(ICMP):
                packet_info['protocol'] = 'ICMP'
                packet_info['port'] = None
                packet_info['flags'] = []
                
            elif packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                packet_info['protocol'] = 'TCP'
                packet_info['port'] = tcp_layer.dport
                
                # Extract TCP flags
                flags = []
                if tcp_layer.flags.S:
                    flags.append('SYN')
                if tcp_layer.flags.A:
                    flags.append('ACK')
                if tcp_layer.flags.F:
                    flags.append('FIN')
                if tcp_layer.flags.R:
                    flags.append('RST')
                packet_info['flags'] = flags
                
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                packet_info['protocol'] = 'UDP'
                packet_info['port'] = udp_layer.dport
                packet_info['flags'] = []
            
            else:
                packet_info['protocol'] = 'OTHER'
                packet_info['port'] = None
                packet_info['flags'] = []
            
            # Analyze with ML
            result = self.detector.analyze_packet(src_ip, packet_info)
            
            # Update statistics
            self.stats['packets_analyzed'] += 1
            
            if result['is_anomaly']:
                self.stats['anomalies_detected'] += 1
                self.stats['attacks_detected'][result['attack_type']] += 1
                
                # Only alert if not in cooldown
                if self._should_alert(src_ip):
                    # Create alert
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
                        'protocol': packet_info['protocol'],
                        'packet_size': packet_info['size']
                    }
                    
                    # Write alert
                    self._write_alert(alert)
                    
                    # Print to console
                    print(f"\n{'='*60}")
                    print(f"🚨 ML ALERT - {result['attack_type']}")
                    print(f"{'='*60}")
                    print(f"Time:       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"Source IP:  {src_ip}")
                    print(f"Dest IP:    {dst_ip}")
                    print(f"Confidence: {result['confidence']:.1f}%")
                    print(f"Threat:     {result['threat_score']}/100")
                    print(f"Protocol:   {packet_info['protocol']}")
                    
                    # Block if necessary
                    if result['should_block']:
                        self._block_ip(src_ip, result['reason'])
                        print(f"Action:     ⛔ IP BLOCKED")
                    else:
                        print(f"Action:     ⚠️  Warning logged")
                    
                    print('='*60 + '\n')
                    
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def start_monitoring(self):
        """Start packet capture and monitoring"""
        print("\n" + "="*60)
        print("🔍 Starting ML Network Monitoring")
        print("="*60)
        print(f"Monitoring interface: {self.interface}")
        print("Press Ctrl+C to stop")
        print("="*60 + "\n")
        
        try:
            # Start packet capture
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                store=False,
                stop_filter=lambda x: not self.running
            )
        except PermissionError:
            print("\n❌ ERROR: Permission denied!")
            print("   Run with sudo: sudo python3 ml_monitor.py")
            sys.exit(1)
        except OSError as e:
            if "No such device" in str(e):
                print(f"\n❌ ERROR: Interface '{self.interface}' not found!")
                print("\nAvailable interfaces:")
                os.system("ip link show | grep -E '^[0-9]+:' | awk '{print $2}' | sed 's/:$//'")
                print("\nTry running after starting the topology:")
                print("   sudo ./scripts/start_topology.sh")
            else:
                print(f"\n❌ ERROR: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ Unexpected error: {e}")
            sys.exit(1)
    
    def _print_final_stats(self):
        """Print final statistics"""
        runtime = time.time() - self.stats['start_time']
        
        print("\n" + "="*60)
        print("📊 ML Monitor - Final Statistics")
        print("="*60)
        print(f"Runtime:            {runtime:.1f} seconds")
        print(f"Packets analyzed:   {self.stats['packets_analyzed']}")
        print(f"Anomalies detected: {self.stats['anomalies_detected']}")
        print(f"IPs blocked:        {self.stats['ips_blocked']}")
        
        if self.stats['attacks_detected']:
            print("\nAttacks by type:")
            for attack_type, count in self.stats['attacks_detected'].items():
                print(f"  {attack_type:15s}: {count}")
        
        print("="*60)


def main():
    """Main entry point"""
    print("""
╔════════════════════════════════════════════════════════════╗
║         ML-BASED SDN INTRUSION DETECTION SYSTEM           ║
║              Real-Time Network Monitor                     ║
╚════════════════════════════════════════════════════════════╝
    """)
    
    # Parse arguments
    interface = sys.argv[1] if len(sys.argv) > 1 else 's1-eth1'
    
    # Create and start monitor
    monitor = MLNetworkMonitor(interface=interface)
    monitor.start_monitoring()


if __name__ == '__main__':
    main()