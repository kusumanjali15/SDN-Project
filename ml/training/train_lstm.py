#!/usr/bin/env python3
"""
Training Script for LSTM Attack Classifier

Usage:
    python train_lstm.py --data /path/to/packets.csv --output /path/to/model
    
Or with CICIDS2017 dataset:
    python train_lstm.py --cicids /path/to/cicids/folder --output /path/to/model
"""

import argparse
import os
import sys
import numpy as np
import pandas as pd
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.preprocessor import SequencePreprocessor, load_cicids_dataset, prepare_train_test_split
from models.lstm_classifier import LSTMClassifier, SimpleLSTMClassifier


def load_training_data(args) -> pd.DataFrame:
    """Load training data from various sources"""
    
    if args.cicids:
        print(f"Loading CICIDS2017 dataset from {args.cicids}")
        csv_files = [f for f in os.listdir(args.cicids) if f.endswith('.csv')]
        
        dfs = []
        for csv_file in csv_files[:3]:  # Limit files for memory
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


def prepare_sequences(df: pd.DataFrame, args) -> tuple:
    """Prepare sequences for LSTM training"""
    
    # Map feature columns from CICIDS to our format
    # CICIDS columns: Destination Port, Flow Duration, Total Fwd Packets, etc.
    
    feature_mapping = {
        'destination_port': 'dst_port',
        'dest_port': 'dst_port',
        'source_port': 'src_port',
        'src_port': 'src_port',
        'protocol': 'protocol',
        'total_length_of_fwd_packets': 'packet_size',
        'flow_bytes/s': 'bytes_per_sec',
        'flow_packets/s': 'packets_per_sec',
    }
    
    # Rename columns
    df_renamed = df.rename(columns={k: v for k, v in feature_mapping.items() if k in df.columns})
    
    # Create packet_size if not present
    if 'packet_size' not in df_renamed.columns:
        if 'total_fwd_packets' in df_renamed.columns and 'total_length_of_fwd_packets' in df_renamed.columns:
            df_renamed['packet_size'] = df_renamed['total_length_of_fwd_packets'] / (df_renamed['total_fwd_packets'] + 1)
        else:
            # Use a proxy
            numeric_cols = df_renamed.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 0:
                df_renamed['packet_size'] = df_renamed[numeric_cols[0]]
            else:
                df_renamed['packet_size'] = 0
    
    # Ensure required columns exist
    required = ['packet_size', 'protocol']
    for col in required:
        if col not in df_renamed.columns:
            df_renamed[col] = 0
    
    # Add tcp_flags if missing
    if 'tcp_flags' not in df_renamed.columns:
        if 'syn_flag_count' in df.columns:
            df_renamed['tcp_flags'] = df['syn_flag_count'] * 2 + df.get('ack_flag_count', 0) * 16
        else:
            df_renamed['tcp_flags'] = 0
    
    # Add port columns if missing
    for col in ['src_port', 'dst_port']:
        if col not in df_renamed.columns:
            df_renamed[col] = 0
    
    print(f"Features available: {list(df_renamed.columns)}")
    
    return df_renamed


def train_model(X_train: np.ndarray, y_train: np.ndarray,
                X_val: np.ndarray, y_val: np.ndarray,
                class_names: list, args):
    """Train LSTM model"""
    
    print("\n" + "="*60)
    print("Training LSTM Attack Classifier")
    print("="*60)
    
    n_features = X_train.shape[2]
    n_classes = len(class_names)
    sequence_length = X_train.shape[1]
    
    print(f"Sequence length: {sequence_length}")
    print(f"Number of features: {n_features}")
    print(f"Number of classes: {n_classes}")
    print(f"Classes: {class_names}")
    
    if args.use_pytorch:
        print("\nUsing PyTorch backend")
        model = SimpleLSTMClassifier(
            sequence_length=sequence_length,
            n_features=n_features,
            n_classes=n_classes,
            hidden_size=args.lstm_units,
            num_layers=2,
            dropout=args.dropout
        )
    else:
        print("\nUsing TensorFlow backend")
        model = LSTMClassifier(
            sequence_length=sequence_length,
            n_features=n_features,
            n_classes=n_classes,
            lstm_units=[args.lstm_units, args.lstm_units // 2],
            dropout=args.dropout
        )
    
    print(f"\nTraining on {len(X_train)} sequences...")
    history = model.fit(
        X_train, y_train,
        X_val=X_val, y_val=y_val,
        epochs=args.epochs,
        batch_size=args.batch_size,
        class_names=class_names
    )
    
    return model, history


def main():
    parser = argparse.ArgumentParser(description="Train LSTM attack classifier")
    
    # Data arguments
    parser.add_argument("--data", type=str, help="Path to CSV data file")
    parser.add_argument("--cicids", type=str, help="Path to CICIDS2017 dataset folder")
    parser.add_argument("--sample-size", type=int, default=50000,
                       help="Sample size per file (default: 50000)")
    
    # Model arguments
    parser.add_argument("--sequence-length", type=int, default=100,
                       help="Sequence length (default: 100)")
    parser.add_argument("--step-size", type=int, default=10,
                       help="Step size between sequences (default: 10)")
    parser.add_argument("--lstm-units", type=int, default=64,
                       help="LSTM hidden units (default: 64)")
    parser.add_argument("--dropout", type=float, default=0.3,
                       help="Dropout rate (default: 0.3)")
    parser.add_argument("--epochs", type=int, default=50,
                       help="Training epochs (default: 50)")
    parser.add_argument("--batch-size", type=int, default=32,
                       help="Batch size (default: 32)")
    parser.add_argument("--use-pytorch", action="store_true",
                       help="Use PyTorch instead of TensorFlow")
    
    # Output arguments
    parser.add_argument("--output", type=str,
                       default="/home/kali/sdn-project/ml/models/trained",
                       help="Output directory for trained models")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Load and prepare data
    df = load_training_data(args)
    df = prepare_sequences(df, args)
    
    # Handle NaN/Inf in numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df[numeric_cols] = df[numeric_cols].fillna(0)
    
    # Create sequence preprocessor
    print("\nCreating sequences...")
    preprocessor = SequencePreprocessor(
        sequence_length=args.sequence_length,
        step_size=args.step_size
    )
    
    # Ensure label column exists
    if 'label' not in df.columns:
        print("Warning: No 'label' column found. Using 'normal' for all samples.")
        df['label'] = 'normal'
    
    # Create sequences
    X, y = preprocessor.create_sequences(df, label_column='label')
    
    print(f"Created {len(X)} sequences")
    print(f"Sequence shape: {X.shape}")
    print(f"Label distribution:")
    unique, counts = np.unique(y, return_counts=True)
    for label, count in zip(unique, counts):
        print(f"  {label}: {count} ({count/len(y)*100:.1f}%)")
    
    # Encode labels
    y_encoded = preprocessor.encode_labels(y)
    class_names = list(preprocessor.label_encoder.classes_)
    
    # Split data
    split = prepare_train_test_split(X, y_encoded, test_size=0.2, val_size=0.1)
    
    X_train = split['X_train']
    X_val = split['X_val']
    X_test = split['X_test']
    y_train = split['y_train']
    y_val = split['y_val']
    y_test = split['y_test']
    
    print(f"\nTraining set: {len(X_train)}")
    print(f"Validation set: {len(X_val)}")
    print(f"Test set: {len(X_test)}")
    
    # Train model
    model, history = train_model(X_train, y_train, X_val, y_val, class_names, args)
    
    # Evaluate on test set
    print("\n" + "="*60)
    print("Evaluation on Test Set")
    print("="*60)
    
    if hasattr(model, 'evaluate'):
        metrics = model.evaluate(X_test, y_test)
        print(f"Test Loss: {metrics['loss']:.4f}")
        print(f"Test Accuracy: {metrics['accuracy']:.4f}")
        print("\nClassification Report:")
        for class_name, class_metrics in metrics['classification_report'].items():
            if isinstance(class_metrics, dict):
                print(f"  {class_name}:")
                print(f"    Precision: {class_metrics.get('precision', 0):.4f}")
                print(f"    Recall: {class_metrics.get('recall', 0):.4f}")
                print(f"    F1-Score: {class_metrics.get('f1-score', 0):.4f}")
    else:
        # PyTorch model - simple evaluation
        y_pred = model.predict(X_test)
        accuracy = np.mean(y_pred == y_test)
        print(f"Test Accuracy: {accuracy:.4f}")
    
    # Save model
    model_path = os.path.join(args.output, "lstm_classifier")
    print(f"\nSaving model to {model_path}")
    model.save(model_path)
    
    # Save preprocessor
    prep_path = os.path.join(args.output, "sequence_preprocessor.pkl")
    print(f"Saving preprocessor to {prep_path}")
    preprocessor.save(prep_path)
    
    print("\n" + "="*60)
    print("Training complete!")
    print("="*60)


if __name__ == "__main__":
    main()
