"""
Random Forest Attack Classifier for SDN-IDS

Alternative to LSTM that works without deep learning frameworks.
Uses flow-level features instead of packet sequences.

Advantages:
- Fast training and inference
- No GPU required
- Interpretable feature importance
- Works well with tabular flow data
"""

import numpy as np
from typing import List, Dict, Optional, Tuple
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
import pickle
import os


class AttackClassifier:
    """
    Random Forest-based attack classifier.
    
    Classifies network flows into attack categories:
    - normal
    - ddos
    - portscan
    - bruteforce
    """
    
    def __init__(self,
                 n_estimators: int = 100,
                 max_depth: int = 20,
                 min_samples_split: int = 5,
                 random_state: int = 42):
        """
        Initialize the attack classifier.
        
        Args:
            n_estimators: Number of trees in the forest
            max_depth: Maximum depth of trees
            min_samples_split: Minimum samples to split a node
            random_state: Random seed
        """
        self.model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            min_samples_split=min_samples_split,
            random_state=random_state,
            n_jobs=-1,
            class_weight='balanced'  # Handle imbalanced classes
        )
        self.label_encoder = LabelEncoder()
        self.feature_names: List[str] = []
        self.class_names: List[str] = []
        self.is_fitted = False
        
    def fit(self, X: np.ndarray, y: np.ndarray, 
            feature_names: Optional[List[str]] = None) -> Dict:
        """
        Train the classifier.
        
        Args:
            X: Feature matrix (n_samples, n_features)
            y: Labels (string or int)
            feature_names: Optional feature names
            
        Returns:
            Training metrics
        """
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        
        # Encode labels if strings
        if isinstance(y[0], str):
            y_encoded = self.label_encoder.fit_transform(y)
            self.class_names = list(self.label_encoder.classes_)
        else:
            y_encoded = y
            self.class_names = [str(i) for i in range(len(np.unique(y)))]
        
        # Train
        self.model.fit(X, y_encoded)
        self.is_fitted = True
        
        # Calculate training accuracy
        train_pred = self.model.predict(X)
        train_accuracy = np.mean(train_pred == y_encoded)
        
        return {
            'train_accuracy': train_accuracy,
            'n_classes': len(self.class_names),
            'class_names': self.class_names
        }
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels"""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get class probabilities"""
        if not self.is_fitted:
            raise ValueError("Model must be fitted before prediction")
        return self.model.predict_proba(X)
    
    def predict_class_name(self, X: np.ndarray) -> List[str]:
        """Predict class names"""
        predictions = self.predict(X)
        return self.label_encoder.inverse_transform(predictions)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """
        Evaluate model on test data.
        
        Args:
            X_test: Test features
            y_test: Test labels
            
        Returns:
            Evaluation metrics
        """
        # Encode labels if strings
        if isinstance(y_test[0], str):
            y_encoded = self.label_encoder.transform(y_test)
        else:
            y_encoded = y_test
        
        y_pred = self.predict(X_test)
        accuracy = np.mean(y_pred == y_encoded)
        
        report = classification_report(
            y_encoded, y_pred,
            target_names=self.class_names,
            output_dict=True
        )
        
        cm = confusion_matrix(y_encoded, y_pred)
        
        return {
            'accuracy': accuracy,
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
            'feature_importance': self.get_feature_importance()
        }
    
    def get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance scores"""
        if not self.is_fitted:
            return {}
        
        importance = self.model.feature_importances_
        return {name: float(imp) for name, imp in zip(self.feature_names, importance)}
    
    def save(self, filepath: str):
        """Save model to file"""
        state = {
            'model': self.model,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'class_names': self.class_names,
            'is_fitted': self.is_fitted
        }
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
    
    def load(self, filepath: str):
        """Load model from file"""
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        self.model = state['model']
        self.label_encoder = state['label_encoder']
        self.feature_names = state['feature_names']
        self.class_names = state['class_names']
        self.is_fitted = state['is_fitted']


class GradientBoostingAttackClassifier:
    """
    Gradient Boosting-based attack classifier.
    
    Alternative to Random Forest with potentially better accuracy
    but slower training.
    """
    
    def __init__(self,
                 n_estimators: int = 100,
                 max_depth: int = 5,
                 learning_rate: float = 0.1,
                 random_state: int = 42):
        """Initialize Gradient Boosting classifier"""
        self.model = GradientBoostingClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            random_state=random_state
        )
        self.label_encoder = LabelEncoder()
        self.feature_names: List[str] = []
        self.class_names: List[str] = []
        self.is_fitted = False
    
    def fit(self, X: np.ndarray, y: np.ndarray,
            feature_names: Optional[List[str]] = None) -> Dict:
        """Train the classifier"""
        self.feature_names = feature_names or [f"feature_{i}" for i in range(X.shape[1])]
        
        if isinstance(y[0], str):
            y_encoded = self.label_encoder.fit_transform(y)
            self.class_names = list(self.label_encoder.classes_)
        else:
            y_encoded = y
            self.class_names = [str(i) for i in range(len(np.unique(y)))]
        
        self.model.fit(X, y_encoded)
        self.is_fitted = True
        
        train_pred = self.model.predict(X)
        train_accuracy = np.mean(train_pred == y_encoded)
        
        return {
            'train_accuracy': train_accuracy,
            'n_classes': len(self.class_names),
            'class_names': self.class_names
        }
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict class labels"""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        return self.model.predict(X)
    
    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Get class probabilities"""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        return self.model.predict_proba(X)
    
    def predict_class_name(self, X: np.ndarray) -> List[str]:
        """Predict class names"""
        predictions = self.predict(X)
        return self.label_encoder.inverse_transform(predictions)
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict:
        """Evaluate on test data"""
        if isinstance(y_test[0], str):
            y_encoded = self.label_encoder.transform(y_test)
        else:
            y_encoded = y_test
        
        y_pred = self.predict(X_test)
        accuracy = np.mean(y_pred == y_encoded)
        
        report = classification_report(
            y_encoded, y_pred,
            target_names=self.class_names,
            output_dict=True
        )
        
        return {
            'accuracy': accuracy,
            'classification_report': report,
            'feature_importance': dict(zip(self.feature_names, self.model.feature_importances_))
        }
    
    def save(self, filepath: str):
        """Save model"""
        state = {
            'model': self.model,
            'label_encoder': self.label_encoder,
            'feature_names': self.feature_names,
            'class_names': self.class_names,
            'is_fitted': self.is_fitted
        }
        os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)
    
    def load(self, filepath: str):
        """Load model"""
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        self.model = state['model']
        self.label_encoder = state['label_encoder']
        self.feature_names = state['feature_names']
        self.class_names = state['class_names']
        self.is_fitted = state['is_fitted']
