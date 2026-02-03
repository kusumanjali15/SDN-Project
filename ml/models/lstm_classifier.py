"""
LSTM-based Attack Classifier for SDN-IDS

Classifies network traffic sequences into attack categories:
- Normal
- DDoS
- Port Scan
- Brute Force
- Injection
- Other attacks

Uses sequences of packets to capture temporal patterns.
"""

import numpy as np
from typing import List, Tuple, Optional, Dict
import pickle
import os


class LSTMClassifier:
    """
    LSTM-based classifier for attack type classification.
    
    Takes sequences of packet features and classifies them
    into attack categories.
    """
    
    def __init__(self,
                 sequence_length: int = 100,
                 n_features: int = 5,
                 n_classes: int = 6,
                 lstm_units: List[int] = [64, 32],
                 dropout: float = 0.3):
        """
        Initialize LSTM classifier.
        
        Args:
            sequence_length: Number of packets per sequence
            n_features: Number of features per packet
            n_classes: Number of attack classes
            lstm_units: Units in each LSTM layer
            dropout: Dropout rate
        """
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.n_classes = n_classes
        self.lstm_units = lstm_units
        self.dropout = dropout
        self.model = None
        self.class_names: List[str] = []
        self.is_fitted = False
        
        self._build_model()
    
    def _build_model(self):
        """Build the LSTM architecture"""
        try:
            import tensorflow as tf
            from tensorflow import keras
            from tensorflow.keras import layers
            
            inputs = keras.Input(shape=(self.sequence_length, self.n_features))
            x = inputs
            
            # LSTM layers
            for i, units in enumerate(self.lstm_units):
                return_sequences = (i < len(self.lstm_units) - 1)
                x = layers.LSTM(
                    units,
                    return_sequences=return_sequences,
                    dropout=self.dropout,
                    recurrent_dropout=self.dropout
                )(x)
            
            # Dense layers
            x = layers.Dense(32, activation='relu')(x)
            x = layers.Dropout(self.dropout)(x)
            
            # Output layer
            outputs = layers.Dense(self.n_classes, activation='softmax')(x)
            
            self.model = keras.Model(inputs, outputs)
            self.model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
        except ImportError:
            print("TensorFlow not installed. LSTMClassifier will not work.")
            print("Install with: pip install tensorflow")
            self.model = None
    
    def fit(self,
            X_train: np.ndarray,
            y_train: np.ndarray,
            X_val: Optional[np.ndarray] = None,
            y_val: Optional[np.ndarray] = None,
            epochs: int = 50,
            batch_size: int = 32,
            class_names: Optional[List[str]] = None) -> Dict:
        """
        Train the LSTM classifier.
        
        Args:
            X_train: Training sequences (n_samples, seq_length, n_features)
            y_train: Training labels (integer encoded)
            X_val: Validation sequences
            y_val: Validation labels
            epochs: Training epochs
            batch_size: Batch size
            class_names: Names of classes
            
        Returns:
            Training history
        """
        if self.model is None:
            raise RuntimeError("TensorFlow not available")
        
        self.class_names = class_names or [f"class_{i}" for i in range(self.n_classes)]
        
        validation_data = None
        if X_val is not None and y_val is not None:
            validation_data = (X_val, y_val)
        
        # Add early stopping
        try:
            from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau
            
            callbacks = [
                EarlyStopping(
                    monitor='val_loss' if validation_data else 'loss',
                    patience=5,
                    restore_best_weights=True
                ),
                ReduceLROnPlateau(
                    monitor='val_loss' if validation_data else 'loss',
                    factor=0.5,
                    patience=3
                )
            ]
        except ImportError:
            callbacks = []
        
        history = self.model.fit(
            X_train, y_train,
            validation_data=validation_data,
            epochs=epochs,
            batch_size=batch_size,
            callbacks=callbacks,
            verbose=1
        )
        
        self.is_fitted = True
        return history.history
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Predict class labels for sequences.
        
        Args:
            X: Sequences (n_samples, seq_length, n_features)
            
        Returns:
            Predicted class indices
        """
        if self.model is None or not self.is_fitted:
            raise RuntimeError("Model not fitted")
        
        probs = self.model.predict(X, verbose=0)
        return np.argmax(probs, axis=1)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """
        Get class probabilities.
        
        Args:
            X: Sequences
            
        Returns:
            Class probabilities (n_samples, n_classes)
        """
        if self.model is None or not self.is_fitted:
            raise RuntimeError("Model not fitted")
        
        return self.model.predict(X, verbose=0)
    
    def predict_class_name(self, X: np.ndarray) -> List[str]:
        """
        Predict class names.
        
        Args:
            X: Sequences
            
        Returns:
            List of class names
        """
        indices = self.predict(X)
        return [self.class_names[i] for i in indices]
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """
        Evaluate model on test data.
        
        Args:
            X_test: Test sequences
            y_test: Test labels
            
        Returns:
            Evaluation metrics
        """
        if self.model is None or not self.is_fitted:
            raise RuntimeError("Model not fitted")
        
        loss, accuracy = self.model.evaluate(X_test, y_test, verbose=0)
        
        # Get predictions for detailed metrics
        y_pred = self.predict(X_test)
        
        # Calculate per-class metrics
        from sklearn.metrics import classification_report, confusion_matrix
        
        report = classification_report(
            y_test, y_pred,
            target_names=self.class_names,
            output_dict=True
        )
        
        cm = confusion_matrix(y_test, y_pred)
        
        return {
            'loss': loss,
            'accuracy': accuracy,
            'classification_report': report,
            'confusion_matrix': cm.tolist()
        }
    
    def save(self, filepath: str):
        """Save model to file"""
        if self.model:
            self.model.save(filepath + '.keras')
        
        meta = {
            'sequence_length': self.sequence_length,
            'n_features': self.n_features,
            'n_classes': self.n_classes,
            'lstm_units': self.lstm_units,
            'dropout': self.dropout,
            'class_names': self.class_names,
            'is_fitted': self.is_fitted
        }
        
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath + '.meta', 'wb') as f:
            pickle.dump(meta, f)
    
    def load(self, filepath: str):
        """Load model from file"""
        try:
            from tensorflow import keras
            
            self.model = keras.models.load_model(filepath + '.keras')
            
            with open(filepath + '.meta', 'rb') as f:
                meta = pickle.load(f)
            
            self.sequence_length = meta['sequence_length']
            self.n_features = meta['n_features']
            self.n_classes = meta['n_classes']
            self.lstm_units = meta['lstm_units']
            self.dropout = meta['dropout']
            self.class_names = meta['class_names']
            self.is_fitted = meta['is_fitted']
            
        except ImportError:
            raise RuntimeError("TensorFlow required to load model")
    
    def summary(self):
        """Print model summary"""
        if self.model:
            self.model.summary()
        else:
            print("Model not built (TensorFlow not available)")


class SimpleLSTMClassifier:
    """
    Simplified LSTM classifier using PyTorch (alternative to TensorFlow).
    
    Use this if TensorFlow is not available or preferred.
    """
    
    def __init__(self,
                 sequence_length: int = 100,
                 n_features: int = 5,
                 n_classes: int = 6,
                 hidden_size: int = 64,
                 num_layers: int = 2,
                 dropout: float = 0.3):
        """Initialize PyTorch LSTM classifier"""
        self.sequence_length = sequence_length
        self.n_features = n_features
        self.n_classes = n_classes
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.dropout = dropout
        self.model = None
        self.class_names: List[str] = []
        self.is_fitted = False
        
        self._build_model()
    
    def _build_model(self):
        """Build PyTorch LSTM model"""
        try:
            import torch
            import torch.nn as nn
            
            class LSTMNet(nn.Module):
                def __init__(self, input_size, hidden_size, num_layers, 
                             num_classes, dropout):
                    super().__init__()
                    self.lstm = nn.LSTM(
                        input_size=input_size,
                        hidden_size=hidden_size,
                        num_layers=num_layers,
                        batch_first=True,
                        dropout=dropout if num_layers > 1 else 0
                    )
                    self.fc = nn.Sequential(
                        nn.Linear(hidden_size, 32),
                        nn.ReLU(),
                        nn.Dropout(dropout),
                        nn.Linear(32, num_classes)
                    )
                
                def forward(self, x):
                    lstm_out, _ = self.lstm(x)
                    out = lstm_out[:, -1, :]  # Take last timestep
                    return self.fc(out)
            
            self.model = LSTMNet(
                self.n_features,
                self.hidden_size,
                self.num_layers,
                self.n_classes,
                self.dropout
            )
            
        except ImportError:
            print("PyTorch not installed. SimpleLSTMClassifier will not work.")
            print("Install with: pip install torch")
            self.model = None
    
    def fit(self, X_train: np.ndarray, y_train: np.ndarray,
            epochs: int = 50, batch_size: int = 32,
            learning_rate: float = 0.001,
            class_names: Optional[List[str]] = None) -> Dict:
        """Train the model"""
        if self.model is None:
            raise RuntimeError("PyTorch not available")
        
        import torch
        import torch.nn as nn
        from torch.utils.data import DataLoader, TensorDataset
        
        self.class_names = class_names or [f"class_{i}" for i in range(self.n_classes)]
        
        # Convert to tensors
        X_tensor = torch.FloatTensor(X_train)
        y_tensor = torch.LongTensor(y_train)
        
        dataset = TensorDataset(X_tensor, y_tensor)
        loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
        
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(self.model.parameters(), lr=learning_rate)
        
        history = {'loss': [], 'accuracy': []}
        
        for epoch in range(epochs):
            self.model.train()
            total_loss = 0
            correct = 0
            total = 0
            
            for X_batch, y_batch in loader:
                optimizer.zero_grad()
                outputs = self.model(X_batch)
                loss = criterion(outputs, y_batch)
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                _, predicted = torch.max(outputs, 1)
                total += y_batch.size(0)
                correct += (predicted == y_batch).sum().item()
            
            avg_loss = total_loss / len(loader)
            accuracy = correct / total
            history['loss'].append(avg_loss)
            history['accuracy'].append(accuracy)
            
            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}, Acc: {accuracy:.4f}")
        
        self.is_fitted = True
        return history
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels"""
        if self.model is None or not self.is_fitted:
            raise RuntimeError("Model not fitted")
        
        import torch
        
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X)
            outputs = self.model(X_tensor)
            _, predicted = torch.max(outputs, 1)
            return predicted.numpy()
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get class probabilities"""
        if self.model is None or not self.is_fitted:
            raise RuntimeError("Model not fitted")
        
        import torch
        import torch.nn.functional as F
        
        self.model.eval()
        with torch.no_grad():
            X_tensor = torch.FloatTensor(X)
            outputs = self.model(X_tensor)
            probs = F.softmax(outputs, dim=1)
            return probs.numpy()
    
    def save(self, filepath: str):
        """Save model"""
        if self.model:
            import torch
            torch.save(self.model.state_dict(), filepath + '.pt')
        
        meta = {
            'sequence_length': self.sequence_length,
            'n_features': self.n_features,
            'n_classes': self.n_classes,
            'hidden_size': self.hidden_size,
            'num_layers': self.num_layers,
            'dropout': self.dropout,
            'class_names': self.class_names,
            'is_fitted': self.is_fitted
        }
        
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath + '.meta', 'wb') as f:
            pickle.dump(meta, f)
    
    def load(self, filepath: str):
        """Load model"""
        import torch
        
        with open(filepath + '.meta', 'rb') as f:
            meta = pickle.load(f)
        
        self.sequence_length = meta['sequence_length']
        self.n_features = meta['n_features']
        self.n_classes = meta['n_classes']
        self.hidden_size = meta['hidden_size']
        self.num_layers = meta['num_layers']
        self.dropout = meta['dropout']
        self.class_names = meta['class_names']
        self.is_fitted = meta['is_fitted']
        
        self._build_model()
        self.model.load_state_dict(torch.load(filepath + '.pt'))
