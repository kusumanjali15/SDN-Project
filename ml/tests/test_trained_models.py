#!/usr/bin/env python3
"""
Test the complete ML prediction pipeline with trained models.
"""

import sys
import os
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np
import pandas as pd
from inference.predictor import MLPredictor, create_predictor


def test_predictor():
    """Test the ML predictor with trained models"""
    
    print("=" * 60)
    print("Testing ML Predictor with Trained Models")
    print("=" * 60)
    
    # Create and load predictor
    predictor = create_predictor()
    
    print("\nPredictor Status:")
    status = predictor.get_status()
    for key, value in status.items():
        print(f"  {key}: {value}")
    
    if not predictor.is_loaded:
        print("\n❌ Models not loaded! Cannot continue.")
        return False
    
    # Load test data
    test_path = "/home/kali/sdn-project/ml/data/datasets/sdn_flows_test.csv"
    if not os.path.exists(test_path):
        print(f"\n❌ Test data not found at {test_path}")
        return False
    
    df = pd.read_csv(test_path)
    print(f"\nLoaded {len(df)} test samples")
    
    # Test predictions
    print("\n" + "-" * 60)
    print("Sample Predictions:")
    print("-" * 60)
    
    # Test each attack type
    for label in df['label'].unique():
        sample = df[df['label'] == label].iloc[0]
        
        # Extract features (same as training)
        exclude_cols = ['src_ip', 'dst_ip', 'label', 'timestamp']
        feature_cols = [c for c in df.columns if c not in exclude_cols 
                       and df[c].dtype in ['int64', 'float64']]
        features = sample[feature_cols].values.tolist()
        
        # Predict
        result = predictor.predict_from_features(features)
        
        print(f"\n  Actual: {label}")
        print(f"  Predicted: {result.attack_type} (confidence: {result.attack_confidence:.2%})")
        print(f"  Is Anomaly: {result.is_anomaly} (score: {result.anomaly_score:.3f})")
        print(f"  Recommendation: {result.recommendation}")
        
        # Check correctness
        if result.attack_type == label:
            print(f"  ✓ Correct!")
        else:
            print(f"  ✗ Mismatch (expected {label})")
    
    # Bulk test
    print("\n" + "-" * 60)
    print("Bulk Accuracy Test:")
    print("-" * 60)
    
    correct = 0
    total = 0
    
    exclude_cols = ['src_ip', 'dst_ip', 'label', 'timestamp']
    feature_cols = [c for c in df.columns if c not in exclude_cols 
                   and df[c].dtype in ['int64', 'float64']]
    
    for _, row in df.iterrows():
        features = row[feature_cols].values.tolist()
        result = predictor.predict_from_features(features)
        
        if result.attack_type == row['label']:
            correct += 1
        total += 1
    
    accuracy = correct / total * 100
    print(f"\n  Total samples: {total}")
    print(f"  Correct predictions: {correct}")
    print(f"  Accuracy: {accuracy:.2f}%")
    
    # Print final stats
    print("\n" + "-" * 60)
    print("Prediction Statistics:")
    print("-" * 60)
    stats = predictor.get_status()['statistics']
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    print("\n" + "=" * 60)
    if accuracy > 95:
        print("✓ ML Pipeline Test PASSED!")
    else:
        print("⚠ ML Pipeline Test completed with lower accuracy")
    print("=" * 60)
    
    return accuracy > 90


if __name__ == "__main__":
    success = test_predictor()
    sys.exit(0 if success else 1)
