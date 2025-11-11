#!/usr/bin/env python3
"""
Quick training script to produce a model file for realtime analysis.
This bypasses the full training pipeline and saves models/best_model.pkl.
"""

import os
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score

from data_preprocessing import DataPreprocessor


def main():
    models_dir = os.path.join('models')
    os.makedirs(models_dir, exist_ok=True)

    print("[QuickTrain] Loading and preprocessing training data (sample)...")
    pre = DataPreprocessor()
    # Use a manageable sample to keep this fast; adjust if desired
    X_train, y_train = pre.preprocess_training_data('data/UNSW_NB15_training-set.csv', sample_size=20000)

    # Simple model; good enough to satisfy realtime loader
    print("[QuickTrain] Training RandomForestClassifier...")
    rf = RandomForestClassifier(n_estimators=100, max_depth=None, n_jobs=-1, random_state=42)
    rf.fit(X_train, y_train)

    # Optional: quick score on the same sample (rough, not a valid eval)
    y_pred = rf.predict(X_train)
    acc = accuracy_score(y_train, y_pred)
    print(f"[QuickTrain] Training accuracy on sample: {acc:.4f}")

    # Save to expected path for realtime mode
    model_path = os.path.join(models_dir, 'best_model.pkl')
    joblib.dump(rf, model_path)
    print(f"[QuickTrain] Saved model to {model_path}")

    # Ensure preprocessor exists (main pipeline already saves it, but do it if missing)
    preproc_path = os.path.join(models_dir, 'preprocessor.pkl')
    if not os.path.exists(preproc_path):
        pre.save_preprocessor(preproc_path)
        print(f"[QuickTrain] Saved preprocessor to {preproc_path}")
    else:
        print(f"[QuickTrain] Preprocessor already present at {preproc_path}")


if __name__ == '__main__':
    main()