#!/usr/bin/env python3
"""Train the deauth attack classifier model.

Binary classification: benign deauth vs attack deauth.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cocosentry.features.deauth import DEAUTH_FEATURE_DIM


def load_data(db_path: str) -> tuple[np.ndarray, np.ndarray]:
    """Load labeled deauth baseline data."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT features, label FROM baselines WHERE model_name = 'deauth_classifier' AND label IS NOT NULL"
    ).fetchall()
    conn.close()

    if not rows:
        print("No labeled deauth baseline data found.")
        sys.exit(1)

    X, y = [], []
    for row in rows:
        features = np.frombuffer(row["features"], dtype=np.float32)
        if len(features) == DEAUTH_FEATURE_DIM:
            X.append(features)
            y.append(0 if row["label"] == "benign" else 1)

    print(f"Loaded {len(X)} samples: {y.count(0)} benign, {y.count(1)} attack")
    return np.array(X), np.array(y)


def build_model(input_dim: int) -> "tf.keras.Model":
    import tensorflow as tf

    model = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(input_dim,)),
        tf.keras.layers.Dense(32, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(16, activation="relu"),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(8, activation="relu"),
        tf.keras.layers.Dense(2, activation="softmax"),
    ])

    model.compile(
        optimizer="adam",
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


def main():
    parser = argparse.ArgumentParser(description="Train deauth attack classifier")
    parser.add_argument("--db", required=True, help="Path to cocosentry.db")
    parser.add_argument("--output", default="models/deauth_classifier.tflite")
    parser.add_argument("--epochs", type=int, default=50)
    parser.add_argument("--batch-size", type=int, default=32)

    args = parser.parse_args()

    X, y = load_data(args.db)

    import tensorflow as tf
    from sklearn.model_selection import train_test_split

    X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, random_state=42)

    mean = X_train.mean(axis=0)
    std = X_train.std(axis=0) + 1e-8
    X_train = (X_train - mean) / std
    X_val = (X_val - mean) / std

    model = build_model(DEAUTH_FEATURE_DIM)
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

    np.savez(args.output.replace(".tflite", "_norm.npz"), mean=mean, std=std)

    from training.export_tflite import convert_to_tflite
    convert_to_tflite(model, args.output, X_train)
    print(f"Model saved to {args.output}")


if __name__ == "__main__":
    main()
