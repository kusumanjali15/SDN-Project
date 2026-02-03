# Trained ML Models

This directory stores trained model weights and preprocessors.

## Expected Files After Training

```
trained/
├── anomaly_detector.pkl      # Isolation Forest model
├── lstm_classifier.keras     # TensorFlow LSTM model
├── lstm_classifier.meta      # LSTM metadata
├── flow_preprocessor.pkl     # Flow feature scaler
└── sequence_preprocessor.pkl # Sequence preprocessor
```

## Training Commands

```bash
# Train anomaly detector
python ../training/train_anomaly.py --cicids /path/to/CICIDS2017

# Train LSTM classifier  
python ../training/train_lstm.py --cicids /path/to/CICIDS2017
```
