#!/usr/bin/env python3
"""
Training Script for Anomaly Detection Model

Usage:
    python train_anomaly.py --data /path/to/data.csv --output /path/to/model
    
Or with CICIDS2017 dataset:
    python train_anomaly.py --cicids /path/to/cicids/folder --output /path/to/model
"""

import argparse
import os
import sys
import numpy as np
import pandas as pd
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.preprocessor import FlowPreprocessor, load_cicids_dataset, prepare_train_test_split
from models.anomaly_detector import AnomalyDetector, AutoencoderDetector


def load_training_data(args) -> pd.DataFrame:
    """Load training data from various sources"""
    
    if args.cicids:
        print(f"Loading CICIDS2017 dataset from {args.cicids}")
        # CICIDS2017 has multiple CSV files
        csv_files = [f for f in os.listdir(args.cicids) if f.endswith('.csv')]
        
        dfs = []
        for csv_file in csv_files:
            filepath = os.path.join(args.cicids, csv_file)
            print(f"  Loading {csv_file}...")
            df = load_cicids_dataset(filepath, sample_size=args.sample_size)
            dfs.append(df)
        
        df = pd.concat(dfs, ignore_index=True)
        print(f"Total samples loaded: {len(df)}")
        return df
    
    elif args.data:
        print(f"Loading data from {args.data}")
        df = pd.read_csv(args.data)
        return df
    
    else:
        raise ValueError("Must provide --data or --cicids argument")


def prepare_features(df: pd.DataFrame, label_column: str = 'label') -> tuple:
    """Prepare features for training"""
    
    # Select numeric columns only
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    # Remove label column if present
    if label_column in numeric_cols:
        numeric_cols.remove(label_column)
    
    # Remove columns that might cause issues
    exclude_cols = ['timestamp', 'flow_id', 'src_ip', 'dst_ip']
    feature_cols = [c for c in numeric_cols if c not in exclude_cols]
    
    print(f"Using {len(feature_cols)} features: {feature_cols[:10]}...")
    
    X = df[feature_cols].values
    y = df[label_column].values if label_column in df.columns else None
    
    return X, y, feature_cols


def train_isolation_forest(X_train: np.ndarray, 
                           X_test: np.ndarray,
                           feature_names: list,
                           args) -> AnomalyDetector:
    """Train Isolation Forest model"""
    
    print("\n" + "="*60)
    print("Training Isolation Forest Anomaly Detector")
    print("="*60)
    
    model = AnomalyDetector(
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        random_state=42
    )
    
    print(f"Training on {len(X_train)} samples...")
    model.fit(X_train, feature_names)
    
    # Evaluate
    print("\nEvaluating on test set...")
    predictions = model.predict(X_test)
    anomaly_scores = model.predict_proba(X_test)
    
    n_anomalies = np.sum(predictions == -1)
    anomaly_rate = n_anomalies / len(predictions)
    
    print(f"  Detected anomalies: {n_anomalies} ({anomaly_rate*100:.2f}%)")
    print(f"  Anomaly score range: [{anomaly_scores.min():.4f}, {anomaly_scores.max():.4f}]")
    print(f"  Threshold: {model.threshold:.4f}")
    
    return model


def train_autoencoder(X_train: np.ndarray,
                      X_test: np.ndarray,
                      args) -> AutoencoderDetector:
    """Train Autoencoder model (optional)"""
    
    print("\n" + "="*60)
    print("Training Autoencoder Anomaly Detector")
    print("="*60)
    
    model = AutoencoderDetector(
        input_dim=X_train.shape[1],
        encoding_dim=args.encoding_dim,
        hidden_dims=[64, 32]
    )
    
    print(f"Training on {len(X_train)} samples...")
    model.fit(
        X_train,
        epochs=args.epochs,
        batch_size=args.batch_size,
        validation_split=0.1
    )
    
    # Evaluate
    print("\nEvaluating on test set...")
    predictions = model.predict(X_test)
    reconstruction_errors = model.predict_proba(X_test)
    
    n_anomalies = np.sum(predictions == -1)
    anomaly_rate = n_anomalies / len(predictions)
    
    print(f"  Detected anomalies: {n_anomalies} ({anomaly_rate*100:.2f}%)")
    print(f"  Reconstruction error range: [{reconstruction_errors.min():.4f}, {reconstruction_errors.max():.4f}]")
    print(f"  Threshold: {model.threshold:.4f}")
    
    return model


def main():
    parser = argparse.ArgumentParser(description="Train anomaly detection model")
    
    # Data arguments
    parser.add_argument("--data", type=str, help="Path to CSV data file")
    parser.add_argument("--cicids", type=str, help="Path to CICIDS2017 dataset folder")
    parser.add_argument("--sample-size", type=int, default=100000,
                       help="Sample size per file (default: 100000)")
    
    # Model arguments
    parser.add_argument("--model", type=str, choices=['isolation_forest', 'autoencoder'],
                       default='isolation_forest', help="Model type")
    parser.add_argument("--contamination", type=float, default=0.1,
                       help="Expected contamination ratio (default: 0.1)")
    parser.add_argument("--n-estimators", type=int, default=100,
                       help="Number of trees for Isolation Forest (default: 100)")
    parser.add_argument("--encoding-dim", type=int, default=16,
                       help="Encoding dimension for Autoencoder (default: 16)")
    parser.add_argument("--epochs", type=int, default=50,
                       help="Training epochs for Autoencoder (default: 50)")
    parser.add_argument("--batch-size", type=int, default=32,
                       help="Batch size (default: 32)")
    
    # Output arguments
    parser.add_argument("--output", type=str, 
                       default="/home/kali/sdn-project/ml/models/trained",
                       help="Output directory for trained models")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Load data
    df = load_training_data(args)
    
    # Prepare features
    X, y, feature_names = prepare_features(df)
    
    # Handle NaN/Inf
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    # Preprocess
    print("\nPreprocessing data...")
    preprocessor = FlowPreprocessor(scaler_type='standard')
    X_scaled = preprocessor.fit_transform(X, feature_names)
    
    # Split data
    # For anomaly detection, we train on "normal" traffic only
    if y is not None:
        # Filter to normal traffic for training
        normal_mask = (y == 'normal') | (y == 'BENIGN') | (y == 'benign')
        X_normal = X_scaled[normal_mask]
        X_attack = X_scaled[~normal_mask]
        
        print(f"\nNormal samples: {len(X_normal)}")
        print(f"Attack samples: {len(X_attack)}")
        
        # Split normal data
        train_size = int(0.8 * len(X_normal))
        X_train = X_normal[:train_size]
        X_test_normal = X_normal[train_size:]
        
        # Create mixed test set
        test_size = min(len(X_test_normal), len(X_attack))
        X_test = np.vstack([X_test_normal[:test_size], X_attack[:test_size]])
    else:
        # No labels - use all data
        train_size = int(0.8 * len(X_scaled))
        X_train = X_scaled[:train_size]
        X_test = X_scaled[train_size:]
    
    print(f"\nTraining set size: {len(X_train)}")
    print(f"Test set size: {len(X_test)}")
    
    # Train model
    if args.model == 'isolation_forest':
        model = train_isolation_forest(X_train, X_test, feature_names, args)
        model_path = os.path.join(args.output, "anomaly_detector.pkl")
    else:
        model = train_autoencoder(X_train, X_test, args)
        model_path = os.path.join(args.output, "anomaly_autoencoder")
    
    # Save model
    print(f"\nSaving model to {model_path}")
    model.save(model_path)
    
    # Save preprocessor
    prep_path = os.path.join(args.output, "flow_preprocessor.pkl")
    print(f"Saving preprocessor to {prep_path}")
    preprocessor.save(prep_path)
    
    print("\n" + "="*60)
    print("Training complete!")
    print("="*60)


if __name__ == "__main__":
    main()
