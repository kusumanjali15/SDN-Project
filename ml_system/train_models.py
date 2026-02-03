#!/usr/bin/env python3
"""
ML Model Training Script
Trains anomaly detector and attack classifier using synthetic network traffic data
"""

import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import json
from datetime import datetime

class NetworkTrafficGenerator:
    """Generate synthetic network traffic data for training"""
    
    def generate_normal_traffic(self, n_samples=1000):
        """Generate normal network traffic patterns"""
        data = []
        
        for _ in range(n_samples):
            # Normal traffic characteristics:
            # - Low to moderate packet rate (1-10 pps)
            # - Balanced protocol usage
            # - Few unique ports
            # - Regular packet sizes
            # - Normal inter-arrival times
            
            pps = np.random.uniform(1, 10)
            tcp_ratio = np.random.uniform(0.3, 0.7)
            udp_ratio = np.random.uniform(0.1, 0.4)
            icmp_ratio = 1 - tcp_ratio - udp_ratio
            port_diversity = np.random.randint(1, 5)
            avg_packet_size = np.random.uniform(60, 1500)
            std_packet_size = np.random.uniform(10, 200)
            avg_inter_arrival = np.random.uniform(0.05, 0.5)
            syn_count = np.random.randint(0, 5)
            ack_count = np.random.randint(0, 10)
            fin_count = np.random.randint(0, 3)
            total_packets = np.random.randint(5, 50)
            
            features = [
                pps, tcp_ratio, udp_ratio, icmp_ratio, port_diversity,
                avg_packet_size, std_packet_size, avg_inter_arrival,
                syn_count, ack_count, fin_count, total_packets
            ]
            
            data.append(features)
        
        return np.array(data)
    
    def generate_icmp_flood(self, n_samples=200):
        """Generate ICMP flood attack patterns"""
        data = []
        
        for _ in range(n_samples):
            # ICMP Flood characteristics:
            # - Very high packet rate (20-100+ pps)
            # - 100% ICMP traffic
            # - No port diversity
            # - Small, consistent packet sizes
            # - Very short inter-arrival times
            
            pps = np.random.uniform(20, 100)
            tcp_ratio = 0
            udp_ratio = 0
            icmp_ratio = 1.0
            port_diversity = 0
            avg_packet_size = np.random.uniform(56, 84)  # ICMP typical size
            std_packet_size = np.random.uniform(0, 10)
            avg_inter_arrival = np.random.uniform(0.001, 0.05)
            syn_count = 0
            ack_count = 0
            fin_count = 0
            total_packets = np.random.randint(100, 500)
            
            features = [
                pps, tcp_ratio, udp_ratio, icmp_ratio, port_diversity,
                avg_packet_size, std_packet_size, avg_inter_arrival,
                syn_count, ack_count, fin_count, total_packets
            ]
            
            data.append(features)
        
        return np.array(data)
    
    def generate_syn_flood(self, n_samples=200):
        """Generate SYN flood attack patterns"""
        data = []
        
        for _ in range(n_samples):
            # SYN Flood characteristics:
            # - High packet rate (30-150 pps)
            # - 100% TCP traffic
            # - Many SYN flags, few ACK
            # - Short inter-arrival times
            
            pps = np.random.uniform(30, 150)
            tcp_ratio = 1.0
            udp_ratio = 0
            icmp_ratio = 0
            port_diversity = np.random.randint(1, 10)
            avg_packet_size = np.random.uniform(40, 60)  # SYN packets are small
            std_packet_size = np.random.uniform(5, 15)
            avg_inter_arrival = np.random.uniform(0.001, 0.03)
            syn_count = np.random.randint(100, 500)
            ack_count = np.random.randint(0, 20)
            fin_count = 0
            total_packets = np.random.randint(150, 600)
            
            features = [
                pps, tcp_ratio, udp_ratio, icmp_ratio, port_diversity,
                avg_packet_size, std_packet_size, avg_inter_arrival,
                syn_count, ack_count, fin_count, total_packets
            ]
            
            data.append(features)
        
        return np.array(data)
    
    def generate_udp_flood(self, n_samples=200):
        """Generate UDP flood attack patterns"""
        data = []
        
        for _ in range(n_samples):
            # UDP Flood characteristics:
            # - Very high packet rate (50-200 pps)
            # - 100% UDP traffic
            # - Random ports
            # - Variable packet sizes
            
            pps = np.random.uniform(50, 200)
            tcp_ratio = 0
            udp_ratio = 1.0
            icmp_ratio = 0
            port_diversity = np.random.randint(1, 20)
            avg_packet_size = np.random.uniform(100, 1400)
            std_packet_size = np.random.uniform(50, 300)
            avg_inter_arrival = np.random.uniform(0.001, 0.02)
            syn_count = 0
            ack_count = 0
            fin_count = 0
            total_packets = np.random.randint(200, 800)
            
            features = [
                pps, tcp_ratio, udp_ratio, icmp_ratio, port_diversity,
                avg_packet_size, std_packet_size, avg_inter_arrival,
                syn_count, ack_count, fin_count, total_packets
            ]
            
            data.append(features)
        
        return np.array(data)
    
    def generate_port_scan(self, n_samples=200):
        """Generate port scan patterns"""
        data = []
        
        for _ in range(n_samples):
            # Port Scan characteristics:
            # - Moderate packet rate (10-50 pps)
            # - Mostly TCP with SYN flags
            # - VERY high port diversity
            # - Small packets
            
            pps = np.random.uniform(10, 50)
            tcp_ratio = np.random.uniform(0.8, 1.0)
            udp_ratio = 1 - tcp_ratio
            icmp_ratio = 0
            port_diversity = np.random.randint(20, 100)  # Key indicator!
            avg_packet_size = np.random.uniform(40, 80)
            std_packet_size = np.random.uniform(5, 20)
            avg_inter_arrival = np.random.uniform(0.01, 0.1)
            syn_count = np.random.randint(50, 300)
            ack_count = np.random.randint(0, 30)
            fin_count = np.random.randint(0, 10)
            total_packets = np.random.randint(100, 400)
            
            features = [
                pps, tcp_ratio, udp_ratio, icmp_ratio, port_diversity,
                avg_packet_size, std_packet_size, avg_inter_arrival,
                syn_count, ack_count, fin_count, total_packets
            ]
            
            data.append(features)
        
        return np.array(data)


class ModelTrainer:
    """Train and save ML models"""
    
    def __init__(self, models_dir='models', data_dir='training_data'):
        self.models_dir = models_dir
        self.data_dir = data_dir
        self.feature_names = [
            'packets_per_second', 'tcp_ratio', 'udp_ratio', 'icmp_ratio',
            'port_diversity', 'avg_packet_size', 'std_packet_size',
            'avg_inter_arrival', 'syn_count', 'ack_count', 'fin_count',
            'total_packets'
        ]
        
        # Create directories
        os.makedirs(models_dir, exist_ok=True)
        os.makedirs(data_dir, exist_ok=True)
    
    def generate_training_data(self):
        """Generate all training data"""
        print("📊 Generating synthetic training data...")
        generator = NetworkTrafficGenerator()
        
        # Generate data
        normal = generator.generate_normal_traffic(1000)
        icmp_flood = generator.generate_icmp_flood(200)
        syn_flood = generator.generate_syn_flood(200)
        udp_flood = generator.generate_udp_flood(200)
        port_scan = generator.generate_port_scan(200)
        
        print(f"  ✓ Normal traffic: {len(normal)} samples")
        print(f"  ✓ ICMP Flood: {len(icmp_flood)} samples")
        print(f"  ✓ SYN Flood: {len(syn_flood)} samples")
        print(f"  ✓ UDP Flood: {len(udp_flood)} samples")
        print(f"  ✓ Port Scan: {len(port_scan)} samples")
        
        # Combine data
        X_all = np.vstack([normal, icmp_flood, syn_flood, udp_flood, port_scan])
        
        # Labels for anomaly detection (0=normal, 1=anomaly)
        y_anomaly = np.array(
            [0]*len(normal) + [1]*len(icmp_flood) + [1]*len(syn_flood) + 
            [1]*len(udp_flood) + [1]*len(port_scan)
        )
        
        # Labels for attack classification (0=normal, 1=ICMP, 2=SYN, 3=UDP, 4=PORT_SCAN)
        y_attack = np.array(
            [0]*len(normal) + [1]*len(icmp_flood) + [2]*len(syn_flood) + 
            [3]*len(udp_flood) + [4]*len(port_scan)
        )
        
        # Save datasets
        dataset = {
            'X': X_all.tolist(),
            'y_anomaly': y_anomaly.tolist(),
            'y_attack': y_attack.tolist(),
            'feature_names': self.feature_names,
            'attack_types': {
                0: 'NORMAL',
                1: 'ICMP_FLOOD',
                2: 'SYN_FLOOD',
                3: 'UDP_FLOOD',
                4: 'PORT_SCAN'
            }
        }
        
        dataset_path = os.path.join(self.data_dir, 'training_dataset.json')
        with open(dataset_path, 'w') as f:
            json.dump(dataset, f, indent=2)
        
        print(f"\n✓ Dataset saved to {dataset_path}")
        print(f"  Total samples: {len(X_all)}")
        print(f"  Anomalies: {sum(y_anomaly)} ({sum(y_anomaly)/len(y_anomaly)*100:.1f}%)")
        
        return X_all, y_anomaly, y_attack
    
    def train_anomaly_detector(self, X, y):
        """Train Random Forest for anomaly detection"""
        print("\n🤖 Training Anomaly Detector (Binary Classification)...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train Random Forest
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=10,
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n  Accuracy: {accuracy*100:.2f}%")
        print("\n  Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Anomaly']))
        
        # Feature importance
        print("\n  Top 5 Important Features:")
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1][:5]
        for i, idx in enumerate(indices, 1):
            print(f"    {i}. {self.feature_names[idx]}: {importances[idx]:.4f}")
        
        # Save model
        model_path = os.path.join(self.models_dir, 'anomaly_detector.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        print(f"\n✓ Model saved to {model_path}")
        
        return model, accuracy
    
    def train_attack_classifier(self, X, y):
        """Train Random Forest for attack type classification"""
        print("\n🤖 Training Attack Classifier (Multi-class Classification)...")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train Random Forest
        model = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=5,
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\n  Accuracy: {accuracy*100:.2f}%")
        print("\n  Classification Report:")
        target_names = ['Normal', 'ICMP_Flood', 'SYN_Flood', 'UDP_Flood', 'Port_Scan']
        print(classification_report(y_test, y_pred, target_names=target_names))
        
        print("\n  Confusion Matrix:")
        cm = confusion_matrix(y_test, y_pred)
        print(cm)
        
        # Feature importance
        print("\n  Top 5 Important Features:")
        importances = model.feature_importances_
        indices = np.argsort(importances)[::-1][:5]
        for i, idx in enumerate(indices, 1):
            print(f"    {i}. {self.feature_names[idx]}: {importances[idx]:.4f}")
        
        # Save model
        model_path = os.path.join(self.models_dir, 'attack_classifier.pkl')
        with open(model_path, 'wb') as f:
            pickle.dump(model, f)
        print(f"\n✓ Model saved to {model_path}")
        
        return model, accuracy
    
    def save_training_report(self, anomaly_acc, classifier_acc):
        """Save training summary report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'anomaly_detector_accuracy': float(anomaly_acc),
            'attack_classifier_accuracy': float(classifier_acc),
            'features_used': self.feature_names,
            'models': {
                'anomaly_detector': 'RandomForestClassifier (100 trees)',
                'attack_classifier': 'RandomForestClassifier (150 trees)'
            }
        }
        
        report_path = os.path.join(self.models_dir, 'training_report.json')
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n✓ Training report saved to {report_path}")


def main():
    """Main training pipeline"""
    print("="*60)
    print("ML Network Detector - Training Pipeline")
    print("="*60)
    
    trainer = ModelTrainer()
    
    # Step 1: Generate training data
    X, y_anomaly, y_attack = trainer.generate_training_data()
    
    # Step 2: Train anomaly detector
    anomaly_model, anomaly_acc = trainer.train_anomaly_detector(X, y_anomaly)
    
    # Step 3: Train attack classifier
    classifier_model, classifier_acc = trainer.train_attack_classifier(X, y_attack)
    
    # Step 4: Save report
    trainer.save_training_report(anomaly_acc, classifier_acc)
    
    print("\n" + "="*60)
    print("✓ TRAINING COMPLETE!")
    print("="*60)
    print(f"  Anomaly Detector Accuracy: {anomaly_acc*100:.2f}%")
    print(f"  Attack Classifier Accuracy: {classifier_acc*100:.2f}%")
    print("\nModels are ready for deployment!")


if __name__ == '__main__':
    main()
