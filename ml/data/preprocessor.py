"""
Data Preprocessing Module for SDN-IDS ML Pipeline

Handles data normalization, encoding, and sequence creation
for both anomaly detection and LSTM models.
"""

import numpy as np
import pandas as pd
from typing import List, Tuple, Optional, Dict, Any
from sklearn.preprocessing import StandardScaler, MinMaxScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pickle
import os


class FlowPreprocessor:
    """
    Preprocessor for flow-based features (Anomaly Detection).
    
    Handles normalization and feature scaling for tabular flow data.
    """
    
    def __init__(self, scaler_type: str = "standard"):
        """
        Initialize preprocessor.
        
        Args:
            scaler_type: 'standard' for StandardScaler, 'minmax' for MinMaxScaler
        """
        self.scaler_type = scaler_type
        self.scaler = StandardScaler() if scaler_type == "standard" else MinMaxScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names: List[str] = []
        self.is_fitted = False
        
    def fit(self, X: np.ndarray, feature_names: Optional[List[str]] = None):
        """
        Fit the preprocessor on training data.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            feature_names: Optional list of feature names
        """
        self.scaler.fit(X)
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        self.is_fitted = True
        
    def transform(self, X: np.ndarray) -> np.ndarray:
        """
        Transform features using fitted scaler.
        
        Args:
            X: Feature matrix to transform
            
        Returns:
            Scaled feature matrix
        """
        if not self.is_fitted:
            raise ValueError("Preprocessor must be fitted before transform")
        return self.scaler.transform(X)
    
    def fit_transform(self, X: np.ndarray, 
                      feature_names: Optional[List[str]] = None) -> np.ndarray:
        """Fit and transform in one step"""
        self.fit(X, feature_names)
        return self.transform(X)
    
    def inverse_transform(self, X: np.ndarray) -> np.ndarray:
        """Convert scaled features back to original scale"""
        return self.scaler.inverse_transform(X)
    
    def encode_labels(self, labels: List[str]) -> np.ndarray:
        """Encode string labels to integers"""
        return self.label_encoder.fit_transform(labels)
    
    def decode_labels(self, encoded: np.ndarray) -> List[str]:
        """Decode integer labels back to strings"""
        return self.label_encoder.inverse_transform(encoded)
    
    def save(self, filepath: str):
        """Save preprocessor state to file"""
        state = {
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'scaler_type': self.scaler_type,
            'is_fitted': self.is_fitted
        }
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
    
    def load(self, filepath: str):
        """Load preprocessor state from file"""
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        self.scaler = state['scaler']
        self.label_encoder = state['label_encoder']
        self.feature_names = state['feature_names']
        self.scaler_type = state['scaler_type']
        self.is_fitted = state['is_fitted']


class SequencePreprocessor:
    """
    Preprocessor for sequence-based features (LSTM).
    
    Handles creating sequences of packets for temporal pattern learning.
    """
    
    def __init__(self, 
                 sequence_length: int = 100,
                 step_size: int = 10):
        """
        Initialize sequence preprocessor.
        
        Args:
            sequence_length: Number of packets in each sequence
            step_size: Step between sequences (for overlapping)
        """
        self.sequence_length = sequence_length
        self.step_size = step_size
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns: List[str] = []
        self.is_fitted = False
        
        # Features to use from packet data
        self.packet_features = [
            'packet_size',
            'protocol',
            'src_port',
            'dst_port',
            'tcp_flags',
        ]
        
    def create_sequences(self, 
                         df: pd.DataFrame,
                         label_column: str = 'label') -> Tuple[np.ndarray, np.ndarray]:
        """
        Create sequences from packet DataFrame.
        
        Args:
            df: DataFrame with packet records
            label_column: Name of the label column
            
        Returns:
            X: Sequences array (n_sequences, sequence_length, n_features)
            y: Labels array (n_sequences,)
        """
        # Extract features
        available_features = [f for f in self.packet_features if f in df.columns]
        X_flat = df[available_features].values
        
        # Scale features
        if not self.is_fitted:
            X_flat = self.scaler.fit_transform(X_flat)
            self.is_fitted = True
        else:
            X_flat = self.scaler.transform(X_flat)
        
        # Create sequences
        sequences = []
        labels = []
        
        for i in range(0, len(X_flat) - self.sequence_length + 1, self.step_size):
            seq = X_flat[i:i + self.sequence_length]
            sequences.append(seq)
            
            # Use the most common label in the sequence
            seq_labels = df[label_column].iloc[i:i + self.sequence_length]
            most_common = seq_labels.mode().iloc[0] if not seq_labels.mode().empty else 'normal'
            labels.append(most_common)
        
        X = np.array(sequences)
        y = np.array(labels)
        
        return X, y
    
    def create_sequences_by_flow(self,
                                  df: pd.DataFrame,
                                  flow_columns: List[str] = ['src_ip', 'dst_ip'],
                                  label_column: str = 'label') -> Tuple[np.ndarray, np.ndarray]:
        """
        Create sequences grouped by flow.
        
        Each flow's packets form separate sequences.
        """
        sequences = []
        labels = []
        
        # Group by flow
        for _, flow_df in df.groupby(flow_columns):
            if len(flow_df) >= self.sequence_length:
                X_seq, y_seq = self.create_sequences(
                    flow_df.reset_index(drop=True), 
                    label_column
                )
                sequences.extend(X_seq)
                labels.extend(y_seq)
        
        return np.array(sequences), np.array(labels)
    
    def encode_labels(self, labels: np.ndarray) -> np.ndarray:
        """Encode string labels to integers"""
        return self.label_encoder.fit_transform(labels)
    
    def decode_labels(self, encoded: np.ndarray) -> np.ndarray:
        """Decode integer labels back to strings"""
        return self.label_encoder.inverse_transform(encoded)
    
    def get_num_classes(self) -> int:
        """Get number of unique classes"""
        return len(self.label_encoder.classes_)
    
    def save(self, filepath: str):
        """Save preprocessor state"""
        state = {
            'sequence_length': self.sequence_length,
            'step_size': self.step_size,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'feature_columns': self.feature_columns,
            'packet_features': self.packet_features,
            'is_fitted': self.is_fitted
        }
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
    
    def load(self, filepath: str):
        """Load preprocessor state"""
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        self.sequence_length = state['sequence_length']
        self.step_size = state['step_size']
        self.scaler = state['scaler']
        self.label_encoder = state['label_encoder']
        self.feature_columns = state['feature_columns']
        self.packet_features = state['packet_features']
        self.is_fitted = state['is_fitted']


def load_cicids_dataset(filepath: str, 
                        sample_size: Optional[int] = None) -> pd.DataFrame:
    """
    Load and preprocess CICIDS2017 dataset.
    
    Args:
        filepath: Path to the CSV file
        sample_size: Optional sample size for faster testing
        
    Returns:
        Preprocessed DataFrame
    """
    # Read dataset
    df = pd.read_csv(filepath)
    
    # Sample if needed
    if sample_size and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42)
    
    # Clean column names (CICIDS has spaces)
    df.columns = df.columns.str.strip().str.lower().str.replace(' ', '_')
    
    # Handle infinity and NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    # Map labels to simpler categories
    label_mapping = {
        'BENIGN': 'normal',
        'benign': 'normal',
        'Bot': 'botnet',
        'DDoS': 'ddos',
        'DoS GoldenEye': 'ddos',
        'DoS Hulk': 'ddos',
        'DoS Slowhttptest': 'ddos',
        'DoS slowloris': 'ddos',
        'FTP-Patator': 'bruteforce',
        'SSH-Patator': 'bruteforce',
        'Heartbleed': 'exploit',
        'Infiltration': 'infiltration',
        'PortScan': 'portscan',
        'Web Attack – Brute Force': 'bruteforce',
        'Web Attack – SQL Injection': 'injection',
        'Web Attack – XSS': 'injection',
    }
    
    if 'label' in df.columns:
        df['label'] = df['label'].map(lambda x: label_mapping.get(x, 'attack'))
    
    return df


def prepare_train_test_split(X: np.ndarray, 
                              y: np.ndarray,
                              test_size: float = 0.2,
                              val_size: float = 0.1,
                              random_state: int = 42) -> Dict[str, np.ndarray]:
    """
    Split data into train, validation, and test sets.
    
    Args:
        X: Feature matrix
        y: Labels
        test_size: Fraction for test set
        val_size: Fraction for validation set
        random_state: Random seed
        
    Returns:
        Dictionary with X_train, X_val, X_test, y_train, y_val, y_test
    """
    # First split: train+val and test
    X_temp, X_test, y_temp, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    # Second split: train and val
    val_ratio = val_size / (1 - test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_temp, y_temp, test_size=val_ratio, random_state=random_state, stratify=y_temp
    )
    
    return {
        'X_train': X_train,
        'X_val': X_val,
        'X_test': X_test,
        'y_train': y_train,
        'y_val': y_val,
        'y_test': y_test
    }
