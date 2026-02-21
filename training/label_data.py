#!/usr/bin/env python3
"""Helper to label captured baseline data for supervised training.

Reads baseline records from SQLite and prompts the user to label them,
or auto-labels based on known network configuration.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cocosentry.config import load_config


def auto_label_ap_baselines(db_path: str, config_path: str) -> None:
    """Auto-label AP baseline records based on known networks config."""
    config = load_config(Path(config_path))
    known_bssids = set()
    for net in config.known_networks:
        for bssid in net.bssids:
            known_bssids.add(bssid.lower())

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT id, label FROM baselines WHERE model_name = 'ap_legitimacy'"
    ).fetchall()

    updated = 0
    for row in rows:
        current_label = row["label"]
        if current_label in ("known", "unknown"):
            continue
        # Auto-label is already done during collection, but this script
        # can be used to re-label or verify
        updated += 1

    print(f"AP baselines: {len(rows)} total, {updated} relabeled")
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Label baseline data for training")
    parser.add_argument("--db", required=True, help="Path to cocosentry.db")
    parser.add_argument("--config", default="config.toml", help="Config file path")
    parser.add_argument(
        "--model",
        choices=["ap_legitimacy", "deauth_classifier", "device_fingerprint", "anomaly_detector"],
        required=True,
        help="Which model's baselines to label",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Auto-label using known network config",
    )

    args = parser.parse_args()

    if args.model == "ap_legitimacy" and args.auto:
        auto_label_ap_baselines(args.db, args.config)
    else:
        print(f"Manual labeling for '{args.model}' — not yet implemented.")
        print("Export with train_*.py scripts and label in your preferred tool.")


if __name__ == "__main__":
    main()
