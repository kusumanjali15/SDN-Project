"""
Anomaly Detection Models for SDN-IDS

Implements multiple anomaly detection approaches:
1. Isolation Forest - Fast, interpretable
2. Autoencoder - Deep learning approach (optional)

The models are trained only on normal traffic and detect
anomalies based on deviation from learned patterns.
"""

import numpy as np
from typing import Tuple, Optional, Dict, List
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
import pickle
import os


class AnomalyDetector:
    """
    Anomaly detection using Isolation Forest.
    
    Isolation Forest is effective for high-dimensional data
    and doesn't require labeled anomaly examples for training.
    """
    
    def __init__(self,
                 contamination: float = 0.1,
                 n_estimators: int = 100,
                 max_samples: str = 'auto',
                 random_state: int = 42):
        """
        Initialize the anomaly detector.
        
        Args:
            contamination: Expected proportion of anomalies (for threshold)
            n_estimators: Number of trees in the forest
            max_samples: Samples to use for each tree
            random_state: Random seed for reproducibility
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples=max_samples,
            random_state=random_state,
            n_jobs=-1  # Use all cores
        )
        self.is_fitted = False
        self.threshold = 0.0
        self.feature_names: List[str] = []
        
    def fit(self, X: np.ndarray, feature_names: Optional[List[str]] = None):
        """
        Fit the model on normal traffic data.
        
        Args:
            X: Feature matrix (should be mostly normal traffic)
            feature_names: Optional feature names for interpretability
        """
        self.model.fit(X)
        self.is_fitted = True
        self.feature_names = feature_names or []
        
        # Calculate threshold based on training data
        scores = self.model.decision_function(X)
        self.threshold = np.percentile(scores, 10)  # Bottom 10% are anomalies
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict if samples are normal (1) or anomaly (-1).
        
        Args:
            X: Feature matrix
            
        Returns:
            Array of predictions (1=normal, -1=anomaly)
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get anomaly scores (lower = more anomalous).
        
        Args:
            X: Feature matrix
            
        Returns:
            Array of anomaly scores
        """
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        return self.model.decision_function(X)
    
    def is_anomaly(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Check if samples are anomalies with confidence scores.
        
        Args:
            X: Feature matrix
            
        Returns:
            Tuple of (is_anomaly boolean array, confidence scores)
        """
        scores = self.predict_proba(X)
        predictions = self.predict(X)
        
        # Convert scores to confidence (0-1 range, higher = more anomalous)
        # Isolation Forest scores are typically in range [-0.5, 0.5]
        confidence = 1 - (scores - scores.min()) / (scores.max() - scores.min() + 1e-10)
        
        is_anomaly = predictions == -1
        return is_anomaly, confidence
    
    def save(self, filepath: str):
        """Save the model to a file"""
        state = {
            'model': self.model,
            'is_fitted': self.is_fitted,
            'threshold': self.threshold,
            'feature_names': self.feature_names
        }
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
    
    def load(self, filepath: str):
        """Load the model from a file"""
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        self.model = state['model']
        self.is_fitted = state['is_fitted']
        self.threshold = state['threshold']
        self.feature_names = state['feature_names']


class OneClassSVMDetector:
    """
    Alternative anomaly detector using One-Class SVM.
    
    More sensitive to outliers but slower than Isolation Forest.
    """
    
    def __init__(self,
                 kernel: str = 'rbf',
                 nu: float = 0.1,
                 gamma: str = 'scale'):
        """
        Initialize One-Class SVM detector.
        
        Args:
            kernel: Kernel type ('rbf', 'linear', 'poly')
            nu: Upper bound on fraction of training errors
            gamma: Kernel coefficient
        """
        self.model = OneClassSVM(
            kernel=kernel,
            nu=nu,
            gamma=gamma
        )
        self.is_fitted = False
        
    def fit(self, X: np.ndarray):
        """Fit on normal traffic data"""
        self.model.fit(X)
        self.is_fitted = True
        
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict normal (1) or anomaly (-1)"""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get anomaly scores"""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        return self.model.decision_function(X)
    
    def save(self, filepath: str):
        """Save model to file"""
        with open(filepath, 'wb') as f:
            pickle.dump({'model': self.model, 'is_fitted': self.is_fitted}, f)
    
    def load(self, filepath: str):
        """Load model from file"""
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        self.model = state['model']
        self.is_fitted = state['is_fitted']


# Optional: Autoencoder-based anomaly detection (requires TensorFlow/PyTorch)
class AutoencoderDetector:
    """
    Deep learning anomaly detector using Autoencoder.
    
    Learns to reconstruct normal traffic patterns.
    High reconstruction error indicates anomaly.
    
    Note: Requires TensorFlow. Import will fail gracefully if not installed.
    """
    
    def __init__(self,
                 input_dim: int,
                 encoding_dim: int = 16,
                 hidden_dims: List[int] = [64, 32]):
        """
        Initialize Autoencoder.
        
        Args:
            input_dim: Number of input features
            encoding_dim: Size of the encoding layer
            hidden_dims: Sizes of hidden layers
        """
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.hidden_dims = hidden_dims
        self.model = None
        self.threshold = 0.0
        self.is_fitted = False
        
        self._build_model()
    
    def _build_model(self):
        """Build the autoencoder architecture"""
        try:
            import tensorflow as tf
            from tensorflow import keras
            from tensorflow.keras import layers
            
            # Encoder
            inputs = keras.Input(shape=(self.input_dim,))
            x = inputs
            
            for dim in self.hidden_dims:
                x = layers.Dense(dim, activation='relu')(x)
                x = layers.Dropout(0.2)(x)
            
            # Bottleneck
            encoded = layers.Dense(self.encoding_dim, activation='relu')(x)
            
            # Decoder
            x = encoded
            for dim in reversed(self.hidden_dims):
                x = layers.Dense(dim, activation='relu')(x)
                x = layers.Dropout(0.2)(x)
            
            # Output
            outputs = layers.Dense(self.input_dim, activation='linear')(x)
            
            self.model = keras.Model(inputs, outputs)
            self.model.compile(optimizer='adam', loss='mse')
            
        except ImportError:
            print("TensorFlow not installed. AutoencoderDetector will not work.")
            self.model = None
    
    def fit(self, X: np.ndarray, epochs: int = 50, batch_size: int = 32,
            validation_split: float = 0.1):
        """
        Train the autoencoder on normal traffic.
        
        Args:
            X: Normal traffic feature matrix
            epochs: Training epochs
            batch_size: Batch size
            validation_split: Fraction for validation
        """
        if self.model is None:
            raise RuntimeError("TensorFlow not available")
        
        self.model.fit(
            X, X,  # Input = Output for autoencoder
            epochs=epochs,
            batch_size=batch_size,
            validation_split=validation_split,
            verbose=1
        )
        
        # Calculate threshold from training reconstruction error
        reconstructions = self.model.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        self.threshold = np.percentile(mse, 95)  # 95th percentile
        self.is_fitted = True
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get reconstruction error as anomaly score.
        
        Higher error = more likely anomaly.
        """
        if self.model is None or not self.is_fitted:
            raise RuntimeError("Model not fitted")
        
        reconstructions = self.model.predict(X)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)
        return mse
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict normal (1) or anomaly (-1).
        """
        mse = self.predict_proba(X)
        predictions = np.where(mse > self.threshold, -1, 1)
        return predictions
    
    def save(self, filepath: str):
        """Save model to file"""
        if self.model:
            self.model.save(filepath + '.keras')
        with open(filepath + '.meta', 'wb') as f:
            pickle.dump({
                'threshold': self.threshold,
                'is_fitted': self.is_fitted,
                'input_dim': self.input_dim,
                'encoding_dim': self.encoding_dim,
                'hidden_dims': self.hidden_dims
            }, f)
    
    def load(self, filepath: str):
        """Load model from file"""
        try:
            from tensorflow import keras
            self.model = keras.models.load_model(filepath + '.keras')
            with open(filepath + '.meta', 'rb') as f:
                meta = pickle.load(f)
            self.threshold = meta['threshold']
            self.is_fitted = meta['is_fitted']
        except ImportError:
            raise RuntimeError("TensorFlow required to load model")
