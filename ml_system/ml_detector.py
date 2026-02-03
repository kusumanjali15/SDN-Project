#!/usr/bin/env python3
"""
ML-Based Network Traffic Detector
Provides real-time anomaly detection and attack classification
"""

import numpy as np
import pickle
import os
from datetime import datetime
from collections import defaultdict, deque
import time

class NetworkFeatureExtractor:
    """Extract features from network traffic for ML analysis"""
    
    def __init__(self, window_size=5):
        """
        Args:
            window_size: Time window in seconds for feature aggregation
        """
        self.window_size = window_size
        self.traffic_window = defaultdict(lambda: {
            'packets': deque(maxlen=1000),
            'protocols': defaultdict(int),
            'ports': set(),
            'packet_sizes': [],
            'timestamps': deque(maxlen=1000),
            'flags': defaultdict(int)
        })
        
    def extract_features(self, src_ip, packet_info):
        """
        Extract features from a packet for ML prediction
        
        Args:
            src_ip: Source IP address
            packet_info: Dict with keys: protocol, size, port, timestamp, flags
            
        Returns:
            Feature vector (numpy array)
        """
        window = self.traffic_window[src_ip]
        
        # Add current packet info
        current_time = time.time()
        window['packets'].append(packet_info)
        window['protocols'][packet_info.get('protocol', 'UNKNOWN')] += 1
        window['packet_sizes'].append(packet_info.get('size', 0))
        window['timestamps'].append(current_time)
        
        if 'port' in packet_info and packet_info['port']:
            window['ports'].add(packet_info['port'])
            
        if 'flags' in packet_info:
            for flag in packet_info['flags']:
                window['flags'][flag] += 1
        
        # Clean old data outside window
        cutoff_time = current_time - self.window_size
        while window['timestamps'] and window['timestamps'][0] < cutoff_time:
            window['timestamps'].popleft()
            if window['packets']:
                window['packets'].popleft()
        
        # Calculate features
        features = self._calculate_features(window, current_time)
        return np.array(features).reshape(1, -1)
    
    def _calculate_features(self, window, current_time):
        """Calculate numerical features from traffic window"""
        
        # Feature 1: Packets per second
        time_range = self.window_size
        if len(window['timestamps']) > 1:
            time_range = max(current_time - window['timestamps'][0], 0.1)
        pps = len(window['packets']) / time_range if time_range > 0 else 0
        
        # Feature 2-4: Protocol distribution (TCP, UDP, ICMP percentages)
        total_packets = len(window['packets'])
        tcp_ratio = window['protocols'].get('TCP', 0) / max(total_packets, 1)
        udp_ratio = window['protocols'].get('UDP', 0) / max(total_packets, 1)
        icmp_ratio = window['protocols'].get('ICMP', 0) / max(total_packets, 1)
        
        # Feature 5: Unique ports accessed (port diversity)
        port_diversity = len(window['ports'])
        
        # Feature 6-7: Packet size statistics
        if window['packet_sizes']:
            avg_packet_size = np.mean(window['packet_sizes'])
            std_packet_size = np.std(window['packet_sizes'])
        else:
            avg_packet_size = 0
            std_packet_size = 0
        
        # Feature 8: Inter-arrival time (avg time between packets)
        if len(window['timestamps']) > 1:
            timestamps_list = list(window['timestamps'])
            inter_arrival_times = [timestamps_list[i] - timestamps_list[i-1] 
                                   for i in range(1, len(timestamps_list))]
            avg_inter_arrival = np.mean(inter_arrival_times) if inter_arrival_times else 0
        else:
            avg_inter_arrival = 0
        
        # Feature 9-11: TCP flags distribution (for SYN flood detection)
        syn_count = window['flags'].get('SYN', 0)
        ack_count = window['flags'].get('ACK', 0)
        fin_count = window['flags'].get('FIN', 0)
        
        # Feature 12: Total packets in window
        total_packets_feature = len(window['packets'])
        
        return [
            pps,                    # 0: Packets per second
            tcp_ratio,              # 1: TCP percentage
            udp_ratio,              # 2: UDP percentage
            icmp_ratio,             # 3: ICMP percentage
            port_diversity,         # 4: Number of unique ports
            avg_packet_size,        # 5: Average packet size
            std_packet_size,        # 6: Std dev of packet size
            avg_inter_arrival,      # 7: Avg time between packets
            syn_count,              # 8: SYN flag count
            ack_count,              # 9: ACK flag count
            fin_count,              # 10: FIN flag count
            total_packets_feature   # 11: Total packets in window
        ]
    
    def get_traffic_summary(self, src_ip):
        """Get human-readable traffic summary for an IP"""
        window = self.traffic_window[src_ip]
        
        if not window['packets']:
            return "No recent traffic"
        
        total = len(window['packets'])
        protocols = {k: v for k, v in window['protocols'].items()}
        
        return {
            'total_packets': total,
            'protocols': protocols,
            'unique_ports': len(window['ports']),
            'window_duration': self.window_size
        }


class MLNetworkDetector:
    """Main ML detector for network anomalies and attack classification"""
    
    def __init__(self, models_dir='models'):
        """
        Initialize ML detector
        
        Args:
            models_dir: Directory containing trained models
        """
        self.models_dir = models_dir
        self.feature_extractor = NetworkFeatureExtractor(window_size=5)
        
        # Attack type mapping
        self.attack_types = {
            0: 'NORMAL',
            1: 'ICMP_FLOOD',
            2: 'SYN_FLOOD',
            3: 'UDP_FLOOD',
            4: 'PORT_SCAN'
        }
        
        # Load models
        self.anomaly_model = None
        self.classifier_model = None
        self._load_models()
        
        # Threat scoring
        self.threat_scores = defaultdict(lambda: {'score': 0, 'incidents': []})
        
    def _load_models(self):
        """Load trained ML models"""
        anomaly_path = os.path.join(self.models_dir, 'anomaly_detector.pkl')
        classifier_path = os.path.join(self.models_dir, 'attack_classifier.pkl')
        
        try:
            if os.path.exists(anomaly_path):
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_model = pickle.load(f)
                print(f"✓ Loaded anomaly detection model from {anomaly_path}")
            else:
                print(f"⚠ Anomaly model not found at {anomaly_path}")
                
            if os.path.exists(classifier_path):
                with open(classifier_path, 'rb') as f:
                    self.classifier_model = pickle.load(f)
                print(f"✓ Loaded attack classifier model from {classifier_path}")
            else:
                print(f"⚠ Classifier model not found at {classifier_path}")
                
        except Exception as e:
            print(f"✗ Error loading models: {e}")
    
    def analyze_packet(self, src_ip, packet_info):
        """
        Analyze a single packet and detect anomalies/attacks
        
        Args:
            src_ip: Source IP address
            packet_info: Dictionary with packet details
            
        Returns:
            Detection result dictionary
        """
        # Extract features
        features = self.feature_extractor.extract_features(src_ip, packet_info)
        
        result = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': src_ip,
            'is_anomaly': False,
            'attack_type': 'NORMAL',
            'confidence': 0.0,
            'threat_score': 0,
            'should_block': False,
            'reason': ''
        }
        
        # Check if models are loaded
        if self.anomaly_model is None or self.classifier_model is None:
            result['reason'] = 'Models not loaded'
            return result
        
        try:
            # Step 1: Anomaly Detection
            anomaly_pred = self.anomaly_model.predict(features)[0]
            anomaly_proba = self.anomaly_model.predict_proba(features)[0]
            
            result['is_anomaly'] = bool(anomaly_pred == 1)
            
            if result['is_anomaly']:
                # Step 2: Attack Classification (only if anomaly detected)
                attack_pred = self.classifier_model.predict(features)[0]
                attack_proba = self.classifier_model.predict_proba(features)[0]
                
                result['attack_type'] = self.attack_types.get(attack_pred, 'UNKNOWN')
                result['confidence'] = float(max(attack_proba) * 100)
                
                # Step 3: Calculate threat score
                threat_score = self._calculate_threat_score(
                    src_ip, 
                    result['attack_type'],
                    result['confidence']
                )
                result['threat_score'] = threat_score
                
                # Step 4: Blocking decision
                if threat_score >= 70 and result['attack_type'] != 'NORMAL':
                    result['should_block'] = True
                    result['reason'] = f"{result['attack_type']} detected with {result['confidence']:.1f}% confidence"
                else:
                    result['reason'] = f"Suspicious activity: {result['attack_type']}"
            else:
                result['reason'] = 'Normal traffic'
                
        except Exception as e:
            result['reason'] = f'Analysis error: {str(e)}'
        
        return result
    
    def _calculate_threat_score(self, src_ip, attack_type, confidence):
        """
        Calculate threat score based on attack history and severity
        
        Returns:
            Threat score (0-100)
        """
        # Base score from confidence
        base_score = confidence
        
        # Attack severity multipliers
        severity_multipliers = {
            'ICMP_FLOOD': 1.2,
            'SYN_FLOOD': 1.5,
            'UDP_FLOOD': 1.4,
            'PORT_SCAN': 1.3,
            'NORMAL': 0.5
        }
        
        multiplier = severity_multipliers.get(attack_type, 1.0)
        score = base_score * multiplier
        
        # Add historical component
        threat_history = self.threat_scores[src_ip]
        threat_history['incidents'].append({
            'time': time.time(),
            'type': attack_type,
            'score': score
        })
        
        # Keep only recent incidents (last 60 seconds)
        current_time = time.time()
        threat_history['incidents'] = [
            inc for inc in threat_history['incidents']
            if current_time - inc['time'] < 60
        ]
        
        # Increase score if repeated attacks
        if len(threat_history['incidents']) > 3:
            score *= 1.2
        
        # Cap at 100
        final_score = min(int(score), 100)
        threat_history['score'] = final_score
        
        return final_score
    
    def get_statistics(self):
        """Get detection statistics"""
        stats = {
            'monitored_ips': len(self.feature_extractor.traffic_window),
            'high_threat_ips': sum(1 for ip, data in self.threat_scores.items() 
                                   if data['score'] >= 70),
            'models_loaded': (self.anomaly_model is not None and 
                            self.classifier_model is not None)
        }
        return stats
    
    def reset_ip_history(self, src_ip):
        """Reset threat history for an IP"""
        if src_ip in self.threat_scores:
            del self.threat_scores[src_ip]
        if src_ip in self.feature_extractor.traffic_window:
            del self.feature_extractor.traffic_window[src_ip]


if __name__ == '__main__':
    # Test the detector
    print("ML Network Detector - Test Mode")
    detector = MLNetworkDetector()
    
    # Simulate normal traffic
    print("\n--- Testing Normal Traffic ---")
    for i in range(3):
        packet = {
            'protocol': 'TCP',
            'size': 60,
            'port': 80,
            'timestamp': time.time(),
            'flags': ['SYN', 'ACK']
        }
        result = detector.analyze_packet('10.0.1.1', packet)
        print(f"Packet {i+1}: {result['attack_type']} (Anomaly: {result['is_anomaly']})")
        time.sleep(0.5)
    
    # Simulate ICMP flood
    print("\n--- Testing ICMP Flood ---")
    for i in range(30):
        packet = {
            'protocol': 'ICMP',
            'size': 64,
            'port': None,
            'timestamp': time.time(),
            'flags': []
        }
        result = detector.analyze_packet('10.0.1.2', packet)
        if result['is_anomaly']:
            print(f"🚨 ALERT: {result['attack_type']} - Threat: {result['threat_score']}/100 - Block: {result['should_block']}")
        time.sleep(0.1)
    
    print("\n--- Statistics ---")
    print(detector.get_statistics())
