#!/usr/bin/env python3
"""Train the AP legitimacy classifier model.

Reads labeled baseline data from SQLite and trains a small dense network
for binary classification (legitimate vs rogue AP).
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cocosentry.features.beacon import BEACON_FEATURE_DIM


def load_data(db_path: str) -> tuple[np.ndarray, np.ndarray]:
    """Load labeled AP baseline data from SQLite."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT features, label FROM baselines WHERE model_name = 'ap_legitimacy' AND label IS NOT NULL"
    ).fetchall()
    conn.close()

    if not rows:
        print("No labeled AP baseline data found. Run baseline collection first.")
        sys.exit(1)

    X = []
    y = []
    for row in rows:
        features = np.frombuffer(row["features"], dtype=np.float32)
        if len(features) == BEACON_FEATURE_DIM:
            X.append(features)
            y.append(0 if row["label"] == "known" else 1)  # 0=legitimate, 1=rogue

    print(f"Loaded {len(X)} samples: {y.count(0)} known, {y.count(1)} unknown")
    return np.array(X), np.array(y)


def build_model(input_dim: int) -> "tf.keras.Model":
    """Build a small dense classification network."""
    import tensorflow as tf

    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_dim,)),
        tf.keras.layers.Dense(64, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dense(2, activation="softmax"),
    ])

    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )

    return model


def main():
    parser = argparse.ArgumentParser(description="Train AP legitimacy classifier")
    parser.add_argument("--db", required=True, help="Path to cocosentry.db")
    parser.add_argument("--output", default="models/ap_legitimacy.tflite",
                        help="Output model path")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)

    args = parser.parse_args()

    X, y = load_data(args.db)

    import tensorflow as tf
    from sklearn.model_selection import train_test_split

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    # Normalize features
    mean = X_train.mean(axis=0)
    std = X_train.std(axis=0) + 1e-8
    X_train = (X_train - mean) / std
    X_val = (X_val - mean) / std

    model = build_model(BEACON_FEATURE_DIM)
    model.summary()

    model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=args.epochs,
        batch_size=args.batch_size,
        callbacks=[
            tf.keras.callbacks.EarlyStopping(patience=10, restore_best_weights=True),
        ],
    )

    val_loss, val_acc = model.evaluate(X_val, y_val)
    print(f"\nValidation accuracy: {val_acc:.4f}")

    # Save normalization params alongside model
    np.savez(
        args.output.replace(".tflite", "_norm.npz"),
        mean=mean, std=std,
    )

    # Export to TFLite
    from training.export_tflite import convert_to_tflite
    convert_to_tflite(model, args.output, X_train)
    print(f"Model saved to {args.output}")


if __name__ == "__main__":
    main()
