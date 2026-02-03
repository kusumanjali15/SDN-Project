#!/usr/bin/env python3
"""
Training Script for PyTorch LSTM Attack Classifier

Generates sequence data from flow statistics and trains the LSTM model.
"""

import os
import sys
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.lstm_classifier import SimpleLSTMClassifier


def load_flow_data(filepath: str) -> pd.DataFrame:
    """Load flow data from CSV"""
    print(f"Loading data from {filepath}")
    df = pd.read_csv(filepath)
    print(f"Loaded {len(df)} flows")
    print(f"Labels: {df['label'].value_counts().to_dict()}")
    return df


def create_sequences(df: pd.DataFrame, 
                     sequence_length: int = 20,
                     features: list = None) -> tuple:
    """
    Create sequences from flow data for LSTM training.
    
    Groups flows by source IP and creates overlapping sequences.
    Each sequence represents temporal behavior of a source.
    """
    if features is None:
        features = [
            'packet_count', 'byte_count', 'packets_per_second', 
            'bytes_per_second', 'avg_packet_size'
        ]
    
    print(f"Creating sequences with length {sequence_length}")
    print(f"Features: {features}")
    
    # Encode labels
    le = LabelEncoder()
    df['label_encoded'] = le.fit_transform(df['label'])
    class_names = list(le.classes_)
    print(f"Classes: {class_names}")
    
    # Normalize features
    scaler = StandardScaler()
    df[features] = scaler.fit_transform(df[features])
    
    sequences = []
    labels = []
    
    # Group by source IP to create temporal sequences
    for src_ip in df['src_ip'].unique():
        ip_flows = df[df['src_ip'] == src_ip].sort_index()
        
        if len(ip_flows) < sequence_length:
            continue
        
        # Create overlapping sequences
        for i in range(0, len(ip_flows) - sequence_length + 1, sequence_length // 2):
            seq = ip_flows.iloc[i:i + sequence_length]
            seq_features = seq[features].values
            
            # Use majority label for the sequence
            seq_label = seq['label_encoded'].mode().iloc[0]
            
            sequences.append(seq_features)
            labels.append(seq_label)
    
    # Also create sequences from shuffled data to increase diversity
    print("Generating additional shuffled sequences...")
    for label in df['label'].unique():
        label_df = df[df['label'] == label]
        label_encoded = le.transform([label])[0]
        
        # Create multiple sequences per class
        n_sequences = max(100, len(label_df) // sequence_length)
        
        for _ in range(n_sequences):
            if len(label_df) < sequence_length:
                # Pad with repeated samples
                indices = np.random.choice(len(label_df), sequence_length, replace=True)
            else:
                indices = np.random.choice(len(label_df), sequence_length, replace=False)
            
            seq = label_df.iloc[indices][features].values
            sequences.append(seq)
            labels.append(label_encoded)
    
    X = np.array(sequences)
    y = np.array(labels)
    
    print(f"Created {len(X)} sequences")
    print(f"Sequence shape: {X.shape}")
    
    return X, y, class_names, scaler, le


def train_lstm(X: np.ndarray, y: np.ndarray, 
               class_names: list,
               output_dir: str,
               epochs: int = 100,
               batch_size: int = 32) -> SimpleLSTMClassifier:
    """Train the LSTM classifier"""
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)} sequences")
    print(f"Test set: {len(X_test)} sequences")
    
    # Create model
    n_features = X.shape[2]
    sequence_length = X.shape[1]
    n_classes = len(class_names)
    
    print(f"\nModel configuration:")
    print(f"  Sequence length: {sequence_length}")
    print(f"  Features per step: {n_features}")
    print(f"  Number of classes: {n_classes}")
    
    model = SimpleLSTMClassifier(
        sequence_length=sequence_length,
        n_features=n_features,
        n_classes=n_classes,
        hidden_size=64,
        num_layers=2,
        dropout=0.3
    )
    
    # Train
    print(f"\nTraining for {epochs} epochs...")
    history = model.fit(
        X_train, y_train,
        epochs=epochs,
        batch_size=batch_size,
        class_names=class_names
    )
    
    # Evaluate
    print("\nEvaluating on test set...")
    y_pred = model.predict(X_test)
    
    from sklearn.metrics import classification_report, accuracy_score
    
    accuracy = accuracy_score(y_test, y_pred)
    print(f"\nTest Accuracy: {accuracy:.4f}")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=class_names))
    
    # Save model
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "lstm_classifier")
    model.save(model_path)
    print(f"\nModel saved to {model_path}")
    
    return model


def main():
    """Main training function"""
    print("=" * 60)
    print("LSTM Attack Classifier Training")
    print("=" * 60)
    print(f"Started: {datetime.now()}")
    
    # Paths
    data_dir = "/home/kali/sdn-project/ml/data/datasets"
    output_dir = "/home/kali/sdn-project/ml/models/trained"
    
    # Load data
    flow_file = os.path.join(data_dir, "sdn_flows.csv")
    df = load_flow_data(flow_file)
    
    # Features for sequence
    features = [
        'packet_count', 'byte_count', 'packets_per_second',
        'bytes_per_second', 'avg_packet_size'
    ]
    
    # Create sequences
    X, y, class_names, scaler, label_encoder = create_sequences(
        df, 
        sequence_length=20,
        features=features
    )
    
    # Save scaler and encoder for inference
    import pickle
    with open(os.path.join(output_dir, "lstm_scaler.pkl"), 'wb') as f:
        pickle.dump(scaler, f)
    with open(os.path.join(output_dir, "lstm_label_encoder.pkl"), 'wb') as f:
        pickle.dump(label_encoder, f)
    print(f"Saved scaler and label encoder")
    
    # Train model
    model = train_lstm(
        X, y, 
        class_names=class_names,
        output_dir=output_dir,
        epochs=100,
        batch_size=32
    )
    
    print("\n" + "=" * 60)
    print("Training Complete!")
    print(f"Finished: {datetime.now()}")
    print("=" * 60)


if __name__ == "__main__":
    main()
