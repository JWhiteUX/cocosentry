"""Coral Edge TPU model loader and inference wrapper."""

from __future__ import annotations

import logging
from pathlib import Path

import numpy as np

logger = logging.getLogger(__name__)

# Try to import pycoral, fall back to tflite-runtime (+edgetpu delegate), then tf.lite
_BACKEND = "none"
_make_interpreter = None
_edgetpu_delegate = None

try:
    from pycoral.utils.edgetpu import make_interpreter as _pycoral_make_interpreter
    _make_interpreter = _pycoral_make_interpreter
    _BACKEND = "edgetpu"
    logger.info("Using pycoral Edge TPU backend")
except ImportError:
    try:
        import tflite_runtime.interpreter as tflite
        # Try to load Edge TPU delegate (libedgetpu.so.1 must be installed)
        try:
            _edgetpu_delegate = tflite.load_delegate("libedgetpu.so.1")
            _BACKEND = "edgetpu"
            logger.info("Using tflite-runtime + Edge TPU delegate backend")
        except (ValueError, OSError):
            _BACKEND = "tflite_runtime"
            logger.info("Using tflite-runtime CPU backend")
    except ImportError:
        try:
            import tensorflow as tf
            _BACKEND = "tensorflow"
            logger.info("Using TensorFlow Lite CPU backend")
        except ImportError:
            logger.warning("No TFLite backend available — inference disabled")


class CoralEngine:
    """Manages TFLite model loading and inference.

    Supports Coral Edge TPU when available, falls back to CPU inference.
    """

    def __init__(self, model_dir: Path, use_edgetpu: bool = True):
        self.model_dir = Path(model_dir)
        self.use_edgetpu = use_edgetpu and _BACKEND == "edgetpu"
        self._interpreters: dict[str, object] = {}
        self._input_details: dict[str, list] = {}
        self._output_details: dict[str, list] = {}

    def load_model(self, name: str, filename: str | None = None) -> bool:
        """Load a TFLite model by name.

        Args:
            name: Model identifier (e.g. "ap_legitimacy").
            filename: Model filename. Defaults to "{name}.tflite".

        Returns:
            True if model loaded successfully.
        """
        if filename is None:
            filename = f"{name}.tflite"

        model_path = self.model_dir / filename
        if not model_path.exists():
            logger.warning("Model file not found: %s", model_path)
            return False

        try:
            interpreter = self._create_interpreter(str(model_path))
            interpreter.allocate_tensors()

            self._interpreters[name] = interpreter
            self._input_details[name] = interpreter.get_input_details()
            self._output_details[name] = interpreter.get_output_details()

            input_shape = self._input_details[name][0]["shape"]
            output_shape = self._output_details[name][0]["shape"]
            logger.info(
                "Loaded model '%s': input=%s output=%s (backend=%s)",
                name, input_shape, output_shape,
                "EdgeTPU" if self.use_edgetpu else "CPU",
            )
            return True

        except Exception as e:
            logger.error("Failed to load model '%s': %s", name, e)
            return False

    def _create_interpreter(self, model_path: str):
        """Create a TFLite interpreter with the best available backend."""
        if self.use_edgetpu and _make_interpreter is not None:
            return _make_interpreter(model_path)

        if self.use_edgetpu and _edgetpu_delegate is not None:
            import tflite_runtime.interpreter as tflite
            return tflite.Interpreter(
                model_path=model_path,
                experimental_delegates=[_edgetpu_delegate],
            )

        if _BACKEND in ("tflite_runtime", "edgetpu"):
            import tflite_runtime.interpreter as tflite
            return tflite.Interpreter(model_path=model_path)

        if _BACKEND == "tensorflow":
            import tensorflow as tf
            return tf.lite.Interpreter(model_path=model_path)

        raise RuntimeError("No TFLite backend available")

    def load_all(self) -> dict[str, bool]:
        """Load all .tflite models from model_dir.

        Returns dict of model_name -> loaded_successfully.
        """
        results = {}
        if not self.model_dir.exists():
            logger.warning("Model directory not found: %s", self.model_dir)
            return results

        for path in sorted(self.model_dir.glob("*.tflite")):
            name = path.stem
            results[name] = self.load_model(name, path.name)

        return results

    @property
    def available_models(self) -> list[str]:
        """List loaded model names."""
        return list(self._interpreters.keys())

    def is_loaded(self, name: str) -> bool:
        """Check if a model is loaded."""
        return name in self._interpreters

    def classify(self, model_name: str, features: np.ndarray) -> tuple[int, float]:
        """Run classification inference.

        Args:
            model_name: Name of the loaded model.
            features: Input feature vector (will be reshaped to match model input).

        Returns:
            (class_id, confidence) — highest scoring class and its probability.
        """
        output = self._run(model_name, features)

        # Apply softmax if output doesn't sum to ~1
        if output.sum() > 1.5 or output.min() < 0:
            output = _softmax(output)

        class_id = int(np.argmax(output))
        confidence = float(output[class_id])

        return class_id, confidence

    def detect_anomaly(self, model_name: str, features: np.ndarray) -> float:
        """Run anomaly detection (autoencoder reconstruction error).

        Args:
            model_name: Name of the loaded model.
            features: Input feature vector.

        Returns:
            Anomaly score 0.0-1.0 (higher = more anomalous).
        """
        output = self._run(model_name, features)

        # Reconstruction error (MSE between input and output)
        # Normalize input to match what we compare against
        input_norm = self._normalize(features.flatten()[:len(output.flatten())])
        output_norm = self._normalize(output.flatten())

        mse = float(np.mean((input_norm - output_norm) ** 2))

        # Map MSE to 0-1 score using sigmoid-like scaling
        score = float(1.0 / (1.0 + np.exp(-10 * (mse - 0.5))))

        return min(max(score, 0.0), 1.0)

    def get_raw_output(self, model_name: str, features: np.ndarray) -> np.ndarray:
        """Run inference and return raw output tensor."""
        return self._run(model_name, features)

    def _run(self, model_name: str, features: np.ndarray) -> np.ndarray:
        """Run inference on a model."""
        if model_name not in self._interpreters:
            raise ValueError(f"Model not loaded: {model_name}")

        interpreter = self._interpreters[model_name]
        input_details = self._input_details[model_name]
        output_details = self._output_details[model_name]

        # Prepare input tensor
        input_shape = input_details[0]["shape"]
        input_dtype = input_details[0]["dtype"]

        # Reshape features to match expected input
        flat = features.flatten()
        expected_size = int(np.prod(input_shape[1:]))  # exclude batch dim

        if len(flat) < expected_size:
            # Pad with zeros
            padded = np.zeros(expected_size, dtype=np.float32)
            padded[:len(flat)] = flat
            flat = padded
        elif len(flat) > expected_size:
            flat = flat[:expected_size]

        input_data = flat.reshape(input_shape).astype(input_dtype)

        # Quantization handling
        if input_dtype == np.int8 or input_dtype == np.uint8:
            quant = input_details[0].get("quantization_parameters", {})
            scale = quant.get("scales", [1.0])
            zero_point = quant.get("zero_points", [0])
            if scale and zero_point:
                input_data = (features.flatten()[:expected_size] / scale[0] + zero_point[0])
                input_data = input_data.reshape(input_shape).astype(input_dtype)

        interpreter.set_tensor(input_details[0]["index"], input_data)
        interpreter.invoke()

        output_data = interpreter.get_tensor(output_details[0]["index"])

        # Dequantize output if needed
        output_dtype = output_details[0]["dtype"]
        if output_dtype == np.int8 or output_dtype == np.uint8:
            quant = output_details[0].get("quantization_parameters", {})
            scale = quant.get("scales", [1.0])
            zero_point = quant.get("zero_points", [0])
            if scale and zero_point:
                output_data = (output_data.astype(np.float32) - zero_point[0]) * scale[0]

        return output_data.flatten().astype(np.float32)

    @staticmethod
    def _normalize(arr: np.ndarray) -> np.ndarray:
        """Min-max normalize an array to [0, 1]."""
        mn, mx = arr.min(), arr.max()
        if mx - mn < 1e-8:
            return np.zeros_like(arr)
        return (arr - mn) / (mx - mn)


def _softmax(x: np.ndarray) -> np.ndarray:
    """Compute softmax values."""
    e_x = np.exp(x - np.max(x))
    return e_x / e_x.sum()
