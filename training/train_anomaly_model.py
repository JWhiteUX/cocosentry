#!/usr/bin/env python3
"""Train the anomaly detector (autoencoder) model.

Unsupervised: learns normal RF environment from baseline captures.
Anomalies = high reconstruction error.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cocosentry.features.window import WINDOW_FEATURE_DIM


def load_data(db_path: str) -> np.ndarray:
    """Load anomaly baseline data (unsupervised — no labels needed)."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT features FROM baselines WHERE model_name = 'anomaly_detector'"
    ).fetchall()
    conn.close()

    if not rows:
        print("No anomaly baseline data found. Run baseline collection first.")
        sys.exit(1)

    X = []
    for row in rows:
        features = np.frombuffer(row["features"], dtype=np.float32)
        if len(features) == WINDOW_FEATURE_DIM:
            X.append(features)

    print(f"Loaded {len(X)} window snapshots for autoencoder training")
    return np.array(X)


def build_autoencoder(input_dim: int) -> "tf.keras.Model":
    """Build a small autoencoder for anomaly detection."""
    import tensorflow as tf

    encoder_input = tf.keras.layers.Input(shape=(input_dim,))
    x = tf.keras.layers.Dense(32, activation="relu")(encoder_input)
    x = tf.keras.layers.Dense(16, activation="relu")(x)
    encoded = x

    x = tf.keras.layers.Dense(32, activation="relu")(encoded)
    decoded = tf.keras.layers.Dense(input_dim, activation="linear")(x)

    model = tf.keras.Model(encoder_input, decoded)
    model.compile(optimizer="adam", loss="mse")
    return model


def main():
    parser = argparse.ArgumentParser(description="Train anomaly detector (autoencoder)")
    parser.add_argument("--db", required=True, help="Path to cocosentry.db")
    parser.add_argument("--output", default="models/anomaly_detector.tflite")
    parser.add_argument("--epochs", type=int, default=100)
    parser.add_argument("--batch-size", type=int, default=32)

    args = parser.parse_args()

    X = load_data(args.db)

    import tensorflow as tf

    # Normalize
    mean = X.mean(axis=0)
    std = X.std(axis=0) + 1e-8
    X_norm = (X - mean) / std

    # Split for validation
    split = int(len(X_norm) * 0.8)
    X_train = X_norm[:split]
    X_val = X_norm[split:]

    model = build_autoencoder(WINDOW_FEATURE_DIM)
    model.summary()

    # Autoencoder: input = target (reconstruct the input)
    model.fit(
        X_train, X_train,
        validation_data=(X_val, X_val),
        epochs=args.epochs,
        batch_size=args.batch_size,
        callbacks=[
            tf.keras.callbacks.EarlyStopping(patience=15, restore_best_weights=True),
        ],
    )

    val_loss = model.evaluate(X_val, X_val)
    print(f"\nValidation MSE: {val_loss:.6f}")

    # Compute reconstruction error distribution for threshold setting
    reconstructed = model.predict(X_val)
    errors = np.mean((X_val - reconstructed) ** 2, axis=1)
    print(f"Reconstruction error stats:")
    print(f"  Mean: {errors.mean():.6f}")
    print(f"  Std:  {errors.std():.6f}")
    print(f"  P95:  {np.percentile(errors, 95):.6f}")
    print(f"  P99:  {np.percentile(errors, 99):.6f}")
    print(f"  Max:  {errors.max():.6f}")

    np.savez(args.output.replace(".tflite", "_norm.npz"), mean=mean, std=std)

    from training.export_tflite import convert_to_tflite
    convert_to_tflite(model, args.output, X_train)
    print(f"Model saved to {args.output}")


if __name__ == "__main__":
    main()
