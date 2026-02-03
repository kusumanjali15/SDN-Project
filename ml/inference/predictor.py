"""
Real-time Prediction Interface for SDN-IDS

Combines anomaly detection and attack classification into
a unified prediction pipeline that can be called from
the Ryu controller.

Two-stage approach:
1. Anomaly Detection (Isolation Forest): Is this traffic normal or abnormal?
2. Attack Classification (Random Forest): What type of attack is this?
"""

import numpy as np
from typing import Dict, Tuple, Optional, List
from dataclasses import dataclass
import os
import logging

# Import local modules
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.collector import FlowStats, FlowCollector
from data.preprocessor import FlowPreprocessor
from models.anomaly_detector import AnomalyDetector
from models.attack_classifier import AttackClassifier


@dataclass
class PredictionResult:
    """Result from ML prediction pipeline"""
    # Anomaly detection results
    is_anomaly: bool
    anomaly_score: float  # 0-1, higher = more anomalous
    
    # Classification results
    attack_type: str  # 'normal', 'ddos', 'portscan', 'bruteforce'
    attack_confidence: float  # 0-1
    class_probabilities: Dict[str, float]  # All class probabilities
    
    # Metadata
    flow_key: str  # Source flow identification
    recommendation: str  # 'allow', 'block', 'monitor'
    
    def to_dict(self) -> Dict:
        return {
            'is_anomaly': self.is_anomaly,
            'anomaly_score': self.anomaly_score,
            'attack_type': self.attack_type,
            'attack_confidence': self.attack_confidence,
            'class_probabilities': self.class_probabilities,
            'flow_key': self.flow_key,
            'recommendation': self.recommendation
        }


class MLPredictor:
    """
    Main prediction interface combining both models.
    
    Pipeline:
    1. Anomaly Detection: Is this traffic normal or abnormal?
    2. Attack Classification: What type of attack?
    3. Decision: Block, monitor, or allow?
    """
    
    def __init__(self,
                 model_dir: str = "/home/kali/sdn-project/ml/models/trained",
                 anomaly_threshold: float = 0.6,
                 classification_threshold: float = 0.7):
        """
        Initialize the ML predictor.
        
        Args:
            model_dir: Directory containing trained models
            anomaly_threshold: Threshold for anomaly detection (0-1)
            classification_threshold: Confidence threshold for attack classification
        """
        self.model_dir = model_dir
        self.anomaly_threshold = anomaly_threshold
        self.classification_threshold = classification_threshold
        
        self.logger = logging.getLogger("MLPredictor")
        
        # Models (loaded lazily)
        self.anomaly_detector: Optional[AnomalyDetector] = None
        self.attack_classifier: Optional[AttackClassifier] = None
        
        # Preprocessor
        self.flow_preprocessor: Optional[FlowPreprocessor] = None
        
        # Flow collector for tracking flows
        self.flow_collector = FlowCollector()
        
        # Statistics
        self.stats = {
            'total_predictions': 0,
            'anomalies_detected': 0,
            'attacks_classified': 0,
            'blocks_recommended': 0
        }
        
        self.is_loaded = False
    
    def load_models(self) -> bool:
        """
        Load trained models from disk.
        
        Returns:
            True if models loaded successfully
        """
        try:
            # Load anomaly detector
            anomaly_path = os.path.join(self.model_dir, "anomaly_detector.pkl")
            if os.path.exists(anomaly_path):
                self.anomaly_detector = AnomalyDetector()
                self.anomaly_detector.load(anomaly_path)
                self.logger.info("✓ Loaded anomaly detector from %s", anomaly_path)
            else:
                self.logger.warning("Anomaly detector not found at %s", anomaly_path)
            
            # Load attack classifier
            classifier_path = os.path.join(self.model_dir, "attack_classifier.pkl")
            if os.path.exists(classifier_path):
                self.attack_classifier = AttackClassifier()
                self.attack_classifier.load(classifier_path)
                self.logger.info("✓ Loaded attack classifier from %s", classifier_path)
                self.logger.info("  Classes: %s", self.attack_classifier.class_names)
            else:
                self.logger.warning("Attack classifier not found at %s", classifier_path)
            
            # Load preprocessor
            prep_path = os.path.join(self.model_dir, "flow_preprocessor.pkl")
            if os.path.exists(prep_path):
                self.flow_preprocessor = FlowPreprocessor()
                self.flow_preprocessor.load(prep_path)
                self.logger.info("✓ Loaded flow preprocessor")
            else:
                self.logger.warning("Flow preprocessor not found at %s", prep_path)
            
            self.is_loaded = (self.anomaly_detector is not None or 
                             self.attack_classifier is not None)
            
            if self.is_loaded:
                self.logger.info("ML Predictor ready!")
            
            return self.is_loaded
            
        except Exception as e:
            self.logger.error("Error loading models: %s", e)
            return False
    
    def predict_flow(self, flow: FlowStats) -> PredictionResult:
        """
        Full prediction pipeline for a flow.
        
        Args:
            flow: FlowStats object with flow statistics
            
        Returns:
            PredictionResult with anomaly detection and classification
        """
        flow_key = f"{flow.src_ip}:{flow.src_port}->{flow.dst_ip}:{flow.dst_port}"
        
        # Default result (normal traffic)
        result = PredictionResult(
            is_anomaly=False,
            anomaly_score=0.0,
            attack_type='normal',
            attack_confidence=1.0,
            class_probabilities={'normal': 1.0},
            flow_key=flow_key,
            recommendation='allow'
        )
        
        self.stats['total_predictions'] += 1
        
        try:
            # Extract features
            features = self.flow_collector.get_flow_features(flow)
            X = np.array([features])
            
            # Preprocess
            if self.flow_preprocessor and self.flow_preprocessor.is_fitted:
                X_scaled = self.flow_preprocessor.transform(X)
            else:
                X_scaled = X
            
            # Stage 1: Anomaly Detection
            if self.anomaly_detector and self.anomaly_detector.is_fitted:
                is_anomaly_arr, anomaly_scores = self.anomaly_detector.is_anomaly(X_scaled)
                result.is_anomaly = is_anomaly_arr[0]
                result.anomaly_score = float(anomaly_scores[0])
                
                if result.is_anomaly:
                    self.stats['anomalies_detected'] += 1
            
            # Stage 2: Attack Classification
            if self.attack_classifier and self.attack_classifier.is_fitted:
                # Get class probabilities
                probs = self.attack_classifier.predict_proba(X_scaled)[0]
                class_names = self.attack_classifier.class_names
                
                # Get predicted class
                predicted_idx = np.argmax(probs)
                result.attack_type = class_names[predicted_idx]
                result.attack_confidence = float(probs[predicted_idx])
                result.class_probabilities = {
                    name: float(probs[i]) for i, name in enumerate(class_names)
                }
                
                if result.attack_type != 'normal':
                    self.stats['attacks_classified'] += 1
            
            # Decision Logic
            result.recommendation = self._make_decision(result)
            
            if result.recommendation == 'block':
                self.stats['blocks_recommended'] += 1
            
        except Exception as e:
            self.logger.error("Error in prediction: %s", e)
        
        return result
    
    def _make_decision(self, result: PredictionResult) -> str:
        """
        Make blocking decision based on both models.
        
        Decision matrix:
        - Anomaly + Attack classified (high conf) -> BLOCK
        - Anomaly + Normal classified -> MONITOR
        - No anomaly + Attack classified (high conf) -> BLOCK (classifier override)
        - No anomaly + Normal classified -> ALLOW
        """
        attack_detected = result.attack_type != 'normal'
        high_confidence = result.attack_confidence > self.classification_threshold
        high_anomaly = result.anomaly_score > self.anomaly_threshold
        
        # Strong signal from classifier - trust it
        if attack_detected and high_confidence:
            return 'block'
        
        # Anomaly detected but classifier says normal - monitor
        if result.is_anomaly and not attack_detected:
            return 'monitor'
        
        # High anomaly score even if classifier unsure
        if high_anomaly:
            return 'monitor'
        
        # Default: allow
        return 'allow'
    
    def predict_from_packet_data(self,
                                  src_ip: str,
                                  dst_ip: str,
                                  src_port: int,
                                  dst_port: int,
                                  protocol: int,
                                  packet_size: int,
                                  tcp_flags: int = 0,
                                  switch_id: int = 0,
                                  in_port: int = 0) -> Optional[PredictionResult]:
        """
        Record a packet and get prediction if enough data.
        
        This method tracks flows and triggers prediction when
        a flow has enough packets for meaningful analysis.
        
        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            src_port: Source port
            dst_port: Destination port
            protocol: IP protocol number
            packet_size: Packet size in bytes
            tcp_flags: TCP flags
            switch_id: SDN switch ID
            in_port: Switch input port
            
        Returns:
            PredictionResult if flow has enough data, None otherwise
        """
        # Record packet and update flow stats
        flow = self.flow_collector.record_packet(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            packet_size=packet_size,
            tcp_flags=tcp_flags,
            switch_id=switch_id,
            in_port=in_port
        )
        
        # Trigger prediction after minimum packets
        MIN_PACKETS_FOR_PREDICTION = 5
        
        if flow.packet_count >= MIN_PACKETS_FOR_PREDICTION:
            # Only predict every N packets to avoid overhead
            if flow.packet_count % 10 == 0 or flow.packet_count == MIN_PACKETS_FOR_PREDICTION:
                return self.predict_flow(flow)
        
        return None
    
    def predict_from_features(self, features: List[float]) -> PredictionResult:
        """
        Direct prediction from feature vector.
        
        Args:
            features: List of 20 flow features
            
        Returns:
            PredictionResult
        """
        result = PredictionResult(
            is_anomaly=False,
            anomaly_score=0.0,
            attack_type='normal',
            attack_confidence=1.0,
            class_probabilities={'normal': 1.0},
            flow_key='direct',
            recommendation='allow'
        )
        
        try:
            X = np.array([features])
            
            if self.flow_preprocessor and self.flow_preprocessor.is_fitted:
                X_scaled = self.flow_preprocessor.transform(X)
            else:
                X_scaled = X
            
            # Anomaly detection
            if self.anomaly_detector and self.anomaly_detector.is_fitted:
                is_anomaly_arr, scores = self.anomaly_detector.is_anomaly(X_scaled)
                result.is_anomaly = is_anomaly_arr[0]
                result.anomaly_score = float(scores[0])
            
            # Classification
            if self.attack_classifier and self.attack_classifier.is_fitted:
                probs = self.attack_classifier.predict_proba(X_scaled)[0]
                class_names = self.attack_classifier.class_names
                predicted_idx = np.argmax(probs)
                result.attack_type = class_names[predicted_idx]
                result.attack_confidence = float(probs[predicted_idx])
                result.class_probabilities = {
                    name: float(probs[i]) for i, name in enumerate(class_names)
                }
            
            result.recommendation = self._make_decision(result)
            
        except Exception as e:
            self.logger.error("Error in direct prediction: %s", e)
        
        return result
    
    def get_status(self) -> Dict:
        """Get predictor status and statistics"""
        return {
            'is_loaded': self.is_loaded,
            'anomaly_detector_ready': (self.anomaly_detector is not None and 
                                       self.anomaly_detector.is_fitted),
            'attack_classifier_ready': (self.attack_classifier is not None and 
                                        self.attack_classifier.is_fitted),
            'preprocessor_ready': (self.flow_preprocessor is not None and 
                                   self.flow_preprocessor.is_fitted),
            'active_flows': len(self.flow_collector.flows),
            'total_packets_processed': self.flow_collector.total_packets,
            'statistics': self.stats
        }
    
    def reset_stats(self):
        """Reset prediction statistics"""
        self.stats = {
            'total_predictions': 0,
            'anomalies_detected': 0,
            'attacks_classified': 0,
            'blocks_recommended': 0
        }


# Convenience function for quick testing
def create_predictor(model_dir: str = "/home/kali/sdn-project/ml/models/trained") -> MLPredictor:
    """Create and load a predictor"""
    predictor = MLPredictor(model_dir=model_dir)
    predictor.load_models()
    return predictor
