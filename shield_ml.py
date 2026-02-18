#!/usr/bin/env python3
"""
PROMPT-SHIELD ML Layer - Optional DeBERTa-v3-base ONNX Inference
Version: 1.0.0

Erkennt Prompt Injection Angriffe mittels fine-tuned DeBERTa-Modell.
Wird nur geladen wenn --ml Flag gesetzt ist.

Requires: pip install -r requirements-ml.txt
  (onnxruntime, tokenizers, huggingface_hub, numpy)

Model: protectai/deberta-v3-base-prompt-injection-v2 (Apache-2.0)
  Trained on 11 datasets, high accuracy on prompt injection detection.
"""

import os
import sys
from pathlib import Path
from typing import Optional, Tuple

# Default cache directory
DEFAULT_MODEL_DIR = Path.home() / ".cache" / "promptshield"
MODEL_REPO = "protectai/deberta-v3-base-prompt-injection-v2"
MODEL_SUBFOLDER = "onnx"


class MLDetector:
    """DeBERTa-v3-base ONNX inference fuer Prompt Injection Erkennung.

    Thread-safe fuer read-only Inference nach Initialisierung.
    Modell wird lazy beim ersten predict()-Aufruf geladen.
    """

    def __init__(self, model_dir: Optional[str] = None):
        self._model_dir = Path(model_dir or os.environ.get(
            "PROMPTSHIELD_MODEL_DIR", str(DEFAULT_MODEL_DIR)
        ))
        self._session = None
        self._tokenizer = None
        self._loaded = False
        self._load_error = None

    @property
    def is_available(self) -> bool:
        """Prueft ob ML-Dependencies installiert sind."""
        try:
            import onnxruntime  # noqa: F401
            import tokenizers   # noqa: F401
            return True
        except ImportError:
            return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def load_error(self) -> Optional[str]:
        return self._load_error

    @property
    def model_name(self) -> str:
        return "deberta-v3-base-prompt-injection-v2"

    @property
    def model_dir(self) -> Path:
        return self._model_dir

    def ensure_model(self, quiet: bool = False) -> bool:
        """Modell herunterladen falls nicht im Cache. Gibt True bei Erfolg zurueck."""
        try:
            from huggingface_hub import hf_hub_download

            self._model_dir.mkdir(parents=True, exist_ok=True)

            # tokenizer.json
            tokenizer_path = self._model_dir / "tokenizer.json"
            if not tokenizer_path.exists():
                if not quiet:
                    print(f"Downloading tokenizer to {self._model_dir}...",
                          file=sys.stderr)
                hf_hub_download(
                    MODEL_REPO, "tokenizer.json",
                    subfolder=MODEL_SUBFOLDER,
                    local_dir=str(self._model_dir),
                    local_dir_use_symlinks=False
                )

            # model.onnx
            model_path = self._model_dir / "model.onnx"
            if not model_path.exists():
                if not quiet:
                    print(f"Downloading ONNX model to {self._model_dir}...",
                          file=sys.stderr)
                hf_hub_download(
                    MODEL_REPO, "model.onnx",
                    subfolder=MODEL_SUBFOLDER,
                    local_dir=str(self._model_dir),
                    local_dir_use_symlinks=False
                )

            return True
        except Exception as e:
            self._load_error = f"Model download failed: {e}"
            return False

    def load(self) -> bool:
        """Modell und Tokenizer laden. Gibt True bei Erfolg zurueck."""
        if self._loaded:
            return True

        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer

            tokenizer_path = self._find_file("tokenizer.json")
            model_path = self._find_file("model.onnx")

            if not tokenizer_path or not model_path:
                # Versuche automatischen Download
                if self.ensure_model(quiet=True):
                    tokenizer_path = self._find_file("tokenizer.json")
                    model_path = self._find_file("model.onnx")

            if not tokenizer_path or not model_path:
                self._load_error = (
                    f"Model files not found in {self._model_dir}. "
                    f"Run: shield.py ml-download"
                )
                return False

            self._tokenizer = Tokenizer.from_file(str(tokenizer_path))

            sess_options = ort.SessionOptions()
            sess_options.graph_optimization_level = (
                ort.GraphOptimizationLevel.ORT_ENABLE_ALL
            )
            sess_options.intra_op_num_threads = 2
            self._session = ort.InferenceSession(
                str(model_path),
                sess_options=sess_options,
                providers=['CPUExecutionProvider']
            )

            self._loaded = True
            self._load_error = None
            return True

        except Exception as e:
            self._load_error = f"Model load failed: {e}"
            return False

    def _find_file(self, filename: str) -> Optional[Path]:
        """Suche Datei in model_dir (flat, onnx/ subfolder, HF cache)."""
        # Direkt
        direct = self._model_dir / filename
        if direct.exists():
            return direct
        # onnx/ Subfolder
        sub = self._model_dir / "onnx" / filename
        if sub.exists():
            return sub
        # HuggingFace Hub Cache Layout
        hf_dir = self._model_dir / f"models--{MODEL_REPO.replace('/', '--')}"
        if hf_dir.exists():
            for p in hf_dir.rglob(filename):
                return p
        return None

    def predict(self, text: str) -> Tuple[float, str]:
        """ML-Inference ausfuehren.

        Returns:
            (confidence, label) - confidence 0.0-1.0 fuer Injection,
            label ist "INJECTION" oder "BENIGN"

        Raises RuntimeError wenn Modell nicht geladen.
        """
        if not self._loaded:
            if not self.load():
                raise RuntimeError(self._load_error or "Model not loaded")

        import numpy as np

        # Tokenize (truncate bei 512 Tokens)
        encoding = self._tokenizer.encode(text)
        ids = encoding.ids[:512]
        mask = encoding.attention_mask[:512]

        input_ids = np.array([ids], dtype=np.int64)
        attention_mask = np.array([mask], dtype=np.int64)

        # Inference
        logits = self._session.run(
            None,
            {"input_ids": input_ids, "attention_mask": attention_mask}
        )

        # Softmax
        scores = self._softmax(logits[0])[0]

        # LABEL_0 = benign, LABEL_1 = injection
        injection_confidence = float(scores[1])
        label = "INJECTION" if injection_confidence >= 0.5 else "BENIGN"

        return injection_confidence, label

    @staticmethod
    def _softmax(x):
        """Numerisch stabile Softmax."""
        import numpy as np
        e_x = np.exp(x - np.max(x, axis=-1, keepdims=True))
        return e_x / e_x.sum(axis=-1, keepdims=True)
