#!/usr/bin/env python3
"""
Training Script for Attack Classifier

Uses Random Forest to classify attacks into categories:
- normal, ddos, portscan, bruteforce

Usage:
    python train_classifier.py --data /path/to/flows.csv --output /path/to/model
"""

import argparse
import os
import sys
import numpy as np
import pandas as pd

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from data.preprocessor import FlowPreprocessor
from models.attack_classifier import AttackClassifier, GradientBoostingAttackClassifier
from sklearn.model_selection import train_test_split


def load_and_prepare_data(filepath: str, sample_size: int = None):
    """Load and prepare data for training"""
    
    print(f"Loading data from {filepath}")
    df = pd.read_csv(filepath)
    
    if sample_size and len(df) > sample_size:
        df = df.sample(n=sample_size, random_state=42)
        print(f"Sampled {sample_size} rows")
    
    # Select numeric features only
    exclude_cols = ['src_ip', 'dst_ip', 'label', 'timestamp']
    feature_cols = [c for c in df.columns if c not in exclude_cols 
                    and df[c].dtype in ['int64', 'float64']]
    
    print(f"Using {len(feature_cols)} features")
    
    X = df[feature_cols].values
    y = df['label'].values
    
    # Handle NaN/Inf
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    return X, y, feature_cols


def main():
    parser = argparse.ArgumentParser(description="Train attack classifier")
    
    parser.add_argument("--data", type=str, required=True,
                       help="Path to training data CSV")
    parser.add_argument("--output", type=str, 
                       default="/home/kali/sdn-project/ml/models/trained",
                       help="Output directory")
    parser.add_argument("--model", type=str, choices=['rf', 'gb'],
                       default='rf', help="Model type: rf=RandomForest, gb=GradientBoosting")
    parser.add_argument("--n-estimators", type=int, default=100,
                       help="Number of trees")
    parser.add_argument("--max-depth", type=int, default=20,
                       help="Max tree depth")
    parser.add_argument("--sample-size", type=int, default=None,
                       help="Sample size for faster training")
    
    args = parser.parse_args()
    
    # Create output directory
    os.makedirs(args.output, exist_ok=True)
    
    # Load data
    X, y, feature_names = load_and_prepare_data(args.data, args.sample_size)
    
    print(f"\nDataset shape: {X.shape}")
    print(f"Label distribution:")
    unique, counts = np.unique(y, return_counts=True)
    for label, count in zip(unique, counts):
        print(f"  {label}: {count} ({count/len(y)*100:.1f}%)")
    
    # Preprocess
    print("\nPreprocessing features...")
    preprocessor = FlowPreprocessor(scaler_type='standard')
    X_scaled = preprocessor.fit_transform(X, feature_names)
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X_scaled, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"\nTraining set: {len(X_train)}")
    print(f"Test set: {len(X_test)}")
    
    # Create and train model
    print("\n" + "=" * 60)
    print(f"Training {'Random Forest' if args.model == 'rf' else 'Gradient Boosting'} Classifier")
    print("=" * 60)
    
    if args.model == 'rf':
        classifier = AttackClassifier(
            n_estimators=args.n_estimators,
            max_depth=args.max_depth,
            random_state=42
        )
    else:
        classifier = GradientBoostingAttackClassifier(
            n_estimators=args.n_estimators,
            max_depth=min(args.max_depth, 10),  # GB works better with shallower trees
            random_state=42
        )
    
    print(f"Training on {len(X_train)} samples...")
    train_metrics = classifier.fit(X_train, y_train, feature_names)
    print(f"Training accuracy: {train_metrics['train_accuracy']*100:.2f}%")
    
    # Evaluate
    print("\n" + "=" * 60)
    print("Evaluation on Test Set")
    print("=" * 60)
    
    eval_metrics = classifier.evaluate(X_test, y_test)
    print(f"Test accuracy: {eval_metrics['accuracy']*100:.2f}%")
    
    print("\nPer-class metrics:")
    for class_name in classifier.class_names:
        metrics = eval_metrics['classification_report'].get(class_name, {})
        print(f"  {class_name}:")
        print(f"    Precision: {metrics.get('precision', 0)*100:.1f}%")
        print(f"    Recall: {metrics.get('recall', 0)*100:.1f}%")
        print(f"    F1-score: {metrics.get('f1-score', 0)*100:.1f}%")
    
    print("\nTop 10 important features:")
    importance = eval_metrics.get('feature_importance', {})
    sorted_importance = sorted(importance.items(), key=lambda x: x[1], reverse=True)[:10]
    for name, imp in sorted_importance:
        print(f"  {name}: {imp:.4f}")
    
    # Save model
    model_path = os.path.join(args.output, "attack_classifier.pkl")
    print(f"\nSaving model to {model_path}")
    classifier.save(model_path)
    
    # Save preprocessor (reuse if exists, otherwise save)
    prep_path = os.path.join(args.output, "flow_preprocessor.pkl")
    if not os.path.exists(prep_path):
        print(f"Saving preprocessor to {prep_path}")
        preprocessor.save(prep_path)
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
