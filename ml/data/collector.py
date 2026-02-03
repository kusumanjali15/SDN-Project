"""
Flow Statistics Collector for SDN-IDS ML Pipeline

This module collects network flow statistics from the Ryu controller
and Suricata alerts for ML model training and inference.
"""

import json
import time
import os
import csv
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict


@dataclass
class FlowStats:
    """Represents statistics for a network flow"""
    # Flow identification
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int  # 1=ICMP, 6=TCP, 17=UDP
    
    # Timing
    start_time: float
    last_seen: float
    duration: float = 0.0
    
    # Packet statistics
    packet_count: int = 0
    byte_count: int = 0
    
    # Packet size statistics
    min_packet_size: int = 0
    max_packet_size: int = 0
    avg_packet_size: float = 0.0
    
    # Rate statistics (calculated)
    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0
    
    # Inter-arrival time statistics
    iat_mean: float = 0.0
    iat_std: float = 0.0
    iat_min: float = 0.0
    iat_max: float = 0.0
    
    # TCP flags (for TCP flows)
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    
    # SDN-specific
    switch_id: int = 0
    in_port: int = 0
    
    # Label (for training data)
    label: str = "normal"  # normal, ddos, portscan, bruteforce, etc.
    
    def update_rates(self):
        """Update rate-based statistics"""
        self.duration = self.last_seen - self.start_time
        if self.duration > 0:
            self.packets_per_second = self.packet_count / self.duration
            self.bytes_per_second = self.byte_count / self.duration


@dataclass 
class PacketRecord:
    """Individual packet record for sequence-based models (LSTM)"""
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    packet_size: int
    tcp_flags: int = 0
    switch_id: int = 0
    in_port: int = 0
    label: str = "normal"


class FlowCollector:
    """
    Collects and aggregates flow statistics from packet events.
    
    This class maintains flow state and computes features suitable
    for ML models (both anomaly detection and LSTM classification).
    """
    
    def __init__(self, 
                 flow_timeout: float = 60.0,
                 output_dir: str = "/tmp/ml_data"):
        """
        Initialize the flow collector.
        
        Args:
            flow_timeout: Seconds of inactivity before flow is considered complete
            output_dir: Directory to save collected data
        """
        self.flow_timeout = flow_timeout
        self.output_dir = output_dir
        self.flows: Dict[Tuple, FlowStats] = {}
        self.packet_buffer: List[PacketRecord] = []
        self.packet_timestamps: Dict[Tuple, List[float]] = defaultdict(list)
        
        # Statistics
        self.total_packets = 0
        self.total_flows = 0
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
    def _get_flow_key(self, src_ip: str, dst_ip: str, 
                      src_port: int, dst_port: int, 
                      protocol: int) -> Tuple:
        """Generate a bidirectional flow key"""
        # Sort to make flow bidirectional
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            return (dst_ip, src_ip, dst_port, src_port, protocol)
    
    def record_packet(self,
                      src_ip: str,
                      dst_ip: str,
                      src_port: int,
                      dst_port: int,
                      protocol: int,
                      packet_size: int,
                      tcp_flags: int = 0,
                      switch_id: int = 0,
                      in_port: int = 0,
                      label: str = "normal") -> FlowStats:
        """
        Record a packet and update flow statistics.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port (0 for ICMP)
            dst_port: Destination port (0 for ICMP)
            protocol: IP protocol number
            packet_size: Size of the packet in bytes
            tcp_flags: TCP flags if applicable
            switch_id: SDN switch ID
            in_port: Switch input port
            label: Traffic label for training
            
        Returns:
            Updated FlowStats object
        """
        current_time = time.time()
        self.total_packets += 1
        
        # Record individual packet for LSTM
        packet = PacketRecord(
            timestamp=current_time,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            tcp_flags=tcp_flags,
            switch_id=switch_id,
            in_port=in_port,
            label=label
        )
        self.packet_buffer.append(packet)
        
        # Get or create flow
        flow_key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)
        
        if flow_key not in self.flows:
            # New flow
            self.flows[flow_key] = FlowStats(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                start_time=current_time,
                last_seen=current_time,
                packet_count=1,
                byte_count=packet_size,
                min_packet_size=packet_size,
                max_packet_size=packet_size,
                avg_packet_size=float(packet_size),
                switch_id=switch_id,
                in_port=in_port,
                label=label
            )
            self.total_flows += 1
            self.packet_timestamps[flow_key] = [current_time]
        else:
            # Update existing flow
            flow = self.flows[flow_key]
            flow.last_seen = current_time
            flow.packet_count += 1
            flow.byte_count += packet_size
            
            # Update packet size stats
            flow.min_packet_size = min(flow.min_packet_size, packet_size)
            flow.max_packet_size = max(flow.max_packet_size, packet_size)
            flow.avg_packet_size = flow.byte_count / flow.packet_count
            
            # Update inter-arrival times
            self.packet_timestamps[flow_key].append(current_time)
            self._update_iat_stats(flow, flow_key)
            
            # Update rates
            flow.update_rates()
            
            # Update TCP flags
            if protocol == 6:  # TCP
                if tcp_flags & 0x02:  # SYN
                    flow.syn_count += 1
                if tcp_flags & 0x10:  # ACK
                    flow.ack_count += 1
                if tcp_flags & 0x01:  # FIN
                    flow.fin_count += 1
                if tcp_flags & 0x04:  # RST
                    flow.rst_count += 1
                if tcp_flags & 0x08:  # PSH
                    flow.psh_count += 1
        
        return self.flows[flow_key]
    
    def _update_iat_stats(self, flow: FlowStats, flow_key: Tuple):
        """Update inter-arrival time statistics for a flow"""
        timestamps = self.packet_timestamps[flow_key]
        if len(timestamps) < 2:
            return
        
        # Calculate IATs
        iats = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
        if iats:
            flow.iat_min = min(iats)
            flow.iat_max = max(iats)
            flow.iat_mean = sum(iats) / len(iats)
            
            # Standard deviation
            if len(iats) > 1:
                variance = sum((x - flow.iat_mean) ** 2 for x in iats) / len(iats)
                flow.iat_std = variance ** 0.5
    
    def get_expired_flows(self) -> List[FlowStats]:
        """Get flows that have timed out"""
        current_time = time.time()
        expired = []
        expired_keys = []
        
        for key, flow in self.flows.items():
            if current_time - flow.last_seen > self.flow_timeout:
                flow.update_rates()
                expired.append(flow)
                expired_keys.append(key)
        
        # Remove expired flows
        for key in expired_keys:
            del self.flows[key]
            if key in self.packet_timestamps:
                del self.packet_timestamps[key]
        
        return expired
    
    def get_all_flows(self) -> List[FlowStats]:
        """Get all current flows (for real-time analysis)"""
        for flow in self.flows.values():
            flow.update_rates()
        return list(self.flows.values())
    
    def get_flow_features(self, flow: FlowStats) -> List[float]:
        """
        Extract feature vector from a flow for ML models.
        
        Returns a list of numerical features suitable for
        anomaly detection models.
        """
        return [
            flow.duration,
            flow.packet_count,
            flow.byte_count,
            flow.packets_per_second,
            flow.bytes_per_second,
            flow.avg_packet_size,
            flow.min_packet_size,
            flow.max_packet_size,
            flow.iat_mean,
            flow.iat_std,
            flow.iat_min,
            flow.iat_max,
            flow.syn_count,
            flow.ack_count,
            flow.fin_count,
            flow.rst_count,
            flow.psh_count,
            float(flow.protocol),
            float(flow.src_port),
            float(flow.dst_port),
        ]
    
    def get_feature_names(self) -> List[str]:
        """Get names of features returned by get_flow_features"""
        return [
            "duration",
            "packet_count",
            "byte_count",
            "packets_per_second",
            "bytes_per_second",
            "avg_packet_size",
            "min_packet_size",
            "max_packet_size",
            "iat_mean",
            "iat_std",
            "iat_min",
            "iat_max",
            "syn_count",
            "ack_count",
            "fin_count",
            "rst_count",
            "psh_count",
            "protocol",
            "src_port",
            "dst_port",
        ]
    
    def save_flows_to_csv(self, filename: Optional[str] = None, 
                          flows: Optional[List[FlowStats]] = None):
        """Save flows to CSV file for training"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.output_dir, f"flows_{timestamp}.csv")
        
        if flows is None:
            flows = self.get_all_flows()
        
        if not flows:
            return filename
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=asdict(flows[0]).keys())
            writer.writeheader()
            for flow in flows:
                writer.writerow(asdict(flow))
        
        return filename
    
    def save_packets_to_csv(self, filename: Optional[str] = None):
        """Save packet records to CSV for LSTM training"""
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(self.output_dir, f"packets_{timestamp}.csv")
        
        if not self.packet_buffer:
            return filename
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=asdict(self.packet_buffer[0]).keys())
            writer.writeheader()
            for packet in self.packet_buffer:
                writer.writerow(asdict(packet))
        
        return filename
    
    def clear_packet_buffer(self):
        """Clear the packet buffer after saving"""
        self.packet_buffer = []
    
    def get_statistics(self) -> Dict:
        """Get collector statistics"""
        return {
            "total_packets": self.total_packets,
            "total_flows": self.total_flows,
            "active_flows": len(self.flows),
            "buffered_packets": len(self.packet_buffer)
        }


class SuricataAlertCollector:
    """
    Collects and parses Suricata alerts for ML labeling.
    
    This is used to label flows based on Suricata detections
    for supervised learning.
    """
    
    def __init__(self, alert_file: str = "/tmp/eve.json"):
        self.alert_file = alert_file
        self.alerts: List[Dict] = []
        self.last_position = 0
        
        # Mapping from Suricata signature categories to ML labels
        self.category_to_label = {
            "attempted-dos": "ddos",
            "attempted-recon": "portscan",
            "attempted-admin": "bruteforce",
            "web-application-attack": "injection",
            "policy-violation": "policy",
            "misc-attack": "other",
        }
    
    def collect_alerts(self) -> List[Dict]:
        """Collect new alerts from Suricata eve.json"""
        new_alerts = []
        
        try:
            if not os.path.exists(self.alert_file):
                return new_alerts
            
            file_size = os.path.getsize(self.alert_file)
            if file_size < self.last_position:
                # File was rotated
                self.last_position = 0
            
            with open(self.alert_file, 'r') as f:
                f.seek(self.last_position)
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            data = json.loads(line)
                            if data.get('event_type') == 'alert':
                                alert = self._parse_alert(data)
                                new_alerts.append(alert)
                                self.alerts.append(alert)
                        except json.JSONDecodeError:
                            pass
                
                self.last_position = f.tell()
        
        except Exception as e:
            print(f"Error collecting alerts: {e}")
        
        return new_alerts
    
    def _parse_alert(self, data: Dict) -> Dict:
        """Parse a Suricata alert into a structured format"""
        alert_info = data.get('alert', {})
        
        return {
            'timestamp': data.get('timestamp'),
            'src_ip': data.get('src_ip'),
            'dst_ip': data.get('dest_ip'),
            'src_port': data.get('src_port', 0),
            'dst_port': data.get('dest_port', 0),
            'protocol': data.get('proto', '').upper(),
            'signature': alert_info.get('signature', ''),
            'signature_id': alert_info.get('signature_id', 0),
            'severity': alert_info.get('severity', 3),
            'category': alert_info.get('category', ''),
            'ml_label': self._get_ml_label(alert_info)
        }
    
    def _get_ml_label(self, alert_info: Dict) -> str:
        """Map Suricata alert category to ML label"""
        category = alert_info.get('category', '').lower()
        
        # Check category mapping
        for cat_pattern, label in self.category_to_label.items():
            if cat_pattern in category:
                return label
        
        # Check signature for keywords
        signature = alert_info.get('signature', '').lower()
        if 'flood' in signature or 'ddos' in signature:
            return 'ddos'
        elif 'scan' in signature:
            return 'portscan'
        elif 'brute' in signature:
            return 'bruteforce'
        elif 'sql' in signature or 'injection' in signature:
            return 'injection'
        
        return 'attack'  # Generic attack label
    
    def get_alerts_for_ip(self, ip: str) -> List[Dict]:
        """Get all alerts involving a specific IP"""
        return [a for a in self.alerts 
                if a['src_ip'] == ip or a['dst_ip'] == ip]
    
    def get_label_for_flow(self, src_ip: str, dst_ip: str, 
                           time_window: float = 60.0) -> str:
        """
        Get ML label for a flow based on Suricata alerts.
        
        If there are alerts for the flow within the time window,
        return the appropriate attack label.
        """
        for alert in reversed(self.alerts):  # Check recent alerts first
            if (alert['src_ip'] == src_ip or alert['dst_ip'] == dst_ip or
                alert['src_ip'] == dst_ip or alert['dst_ip'] == src_ip):
                return alert['ml_label']
        
        return 'normal'
