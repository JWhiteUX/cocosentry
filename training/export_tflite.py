#!/usr/bin/env python3
"""Convert trained Keras models to TFLite format, optionally for Edge TPU.

Supports:
- Standard TFLite (float32)
- Quantized TFLite (int8, required for Edge TPU)
- Edge TPU compilation (requires edgetpu_compiler installed)
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

import numpy as np


def convert_to_tflite(
    model,
    output_path: str,
    representative_data: np.ndarray | None = None,
    quantize: bool = True,
) -> Path:
    """Convert a Keras model to TFLite format.

    Args:
        model: Trained tf.keras.Model
        output_path: Where to save the .tflite file
        representative_data: Sample data for full integer quantization
        quantize: Whether to quantize to int8 (required for Edge TPU)

    Returns:
        Path to the saved .tflite file
    """
    import tensorflow as tf

    converter = tf.lite.TFLiteConverter.from_keras_model(model)

    if quantize and representative_data is not None:
        # Full integer quantization for Edge TPU compatibility
        converter.optimizations = [tf.lite.Optimize.DEFAULT]
        converter.target_spec.supported_ops = [tf.lite.OpsSet.TFLITE_BUILTINS_INT8]
        converter.inference_input_type = tf.int8
        converter.inference_output_type = tf.int8

        def representative_dataset():
            for i in range(min(len(representative_data), 500)):
                sample = representative_data[i:i+1].astype(np.float32)
                yield [sample]

        converter.representative_dataset = representative_dataset
    elif quantize:
        # Dynamic range quantization (no representative data needed)
        converter.optimizations = [tf.lite.Optimize.DEFAULT]

    tflite_model = converter.convert()

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(tflite_model)

    size_kb = len(tflite_model) / 1024
    print(f"TFLite model saved: {out} ({size_kb:.1f} KB)")

    return out


def compile_for_edgetpu(tflite_path: str) -> Path | None:
    """Compile a quantized TFLite model for the Edge TPU.

    Requires `edgetpu_compiler` to be installed.
    The output file will be named *_edgetpu.tflite.
    """
    try:
        result = subprocess.run(
            ["edgetpu_compiler", tflite_path, "-s"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            edgetpu_path = Path(tflite_path).with_suffix("").with_suffix("_edgetpu.tflite")
            # edgetpu_compiler outputs to current dir with _edgetpu suffix
            expected = Path(tflite_path).stem + "_edgetpu.tflite"
            if Path(expected).exists():
                target = Path(tflite_path).parent / expected
                if not target.exists():
                    Path(expected).rename(target)
                edgetpu_path = target
            print(f"Edge TPU model compiled: {edgetpu_path}")
            print(result.stdout)
            return edgetpu_path
        else:
            print(f"Edge TPU compilation failed:\n{result.stderr}")
            return None
    except FileNotFoundError:
        print("edgetpu_compiler not found. Install from:")
        print("  https://coral.ai/docs/accelerator/get-started/#runtime-on-linux")
        return None


def main():
    parser = argparse.ArgumentParser(description="Convert/compile TFLite models")
    parser.add_argument("model_path", help="Path to saved Keras model (.h5 or SavedModel dir)")
    parser.add_argument("--output", "-o", required=True, help="Output .tflite path")
    parser.add_argument("--no-quantize", action="store_true", help="Skip quantization")
    parser.add_argument("--edgetpu", action="store_true", help="Also compile for Edge TPU")

    args = parser.parse_args()

    import tensorflow as tf

    print(f"Loading model from {args.model_path}")
    model = tf.keras.models.load_model(args.model_path)
    model.summary()

    tflite_path = convert_to_tflite(
        model, args.output, quantize=not args.no_quantize,
    )

    if args.edgetpu:
        compile_for_edgetpu(str(tflite_path))


if __name__ == "__main__":
    main()
