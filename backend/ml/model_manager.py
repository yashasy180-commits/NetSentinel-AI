"""
NetSentinel AI
Module 4 - ML Model Manager

Responsible for loading and managing the trained
intrusion-detection model and preprocessing artifact.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib

from ml.model_config import (
    MODEL_PATH,
    PREPROCESSOR_PATH,
    MODEL_METADATA_PATH,
)


class ModelManager:
    """Manage trained ML model artifacts."""

    def __init__(
        self,
        model_path: str | Path = MODEL_PATH,
        preprocessor_path: str | Path = PREPROCESSOR_PATH,
        metadata_path: str | Path = MODEL_METADATA_PATH,
    ) -> None:

        self.model_path = Path(model_path)
        self.preprocessor_path = Path(
            preprocessor_path
        )
        self.metadata_path = Path(metadata_path)

        self.model = None
        self.preprocessor = None
        self.metadata = None

    # =========================================================
    # Validation
    # =========================================================

    def artifacts_exist(self) -> bool:
        """Check whether all required ML artifacts exist."""

        return (
            self.model_path.exists()
            and self.preprocessor_path.exists()
        )

    # =========================================================
    # Loading
    # =========================================================

    def load(self) -> "ModelManager":
        """
        Load the trained model, preprocessor and metadata.
        """

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"ML model not found: {self.model_path}"
            )

        if not self.preprocessor_path.exists():
            raise FileNotFoundError(
                "ML preprocessor not found: "
                f"{self.preprocessor_path}"
            )

        self.model = joblib.load(
            self.model_path
        )

        self.preprocessor = joblib.load(
            self.preprocessor_path
        )

        if self.metadata_path.exists():
            self.metadata = joblib.load(
                self.metadata_path
            )

        return self

    # =========================================================
    # Lazy Loading
    # =========================================================

    def ensure_loaded(self) -> None:
        """Load artifacts if they are not already loaded."""

        if (
            self.model is None
            or self.preprocessor is None
        ):
            self.load()

    # =========================================================
    # Prediction
    # =========================================================

    def predict(
        self,
        feature_rows: list[dict],
    ):
        """
        Generate model predictions from feature dictionaries.
        """

        self.ensure_loaded()

        processed = self.preprocessor.transform(
            feature_rows
        )

        return self.model.predict(
            processed
        )

    def predict_probability(
        self,
        feature_rows: list[dict],
    ):
        """
        Generate class probabilities.
        """

        self.ensure_loaded()

        processed = self.preprocessor.transform(
            feature_rows
        )

        if not hasattr(
            self.model,
            "predict_proba",
        ):
            raise RuntimeError(
                "Loaded ML model does not support "
                "probability prediction."
            )

        return self.model.predict_proba(
            processed
        )

    # =========================================================
    # Metadata
    # =========================================================

    def get_metadata(self) -> dict[str, Any]:
        """Return model metadata."""

        self.ensure_loaded()

        if self.metadata is None:
            return {}

        return dict(
            self.metadata
        )

    def get_model(self):
        """Return the loaded model."""

        self.ensure_loaded()

        return self.model

    def get_preprocessor(self):
        """Return the loaded preprocessor."""

        self.ensure_loaded()

        return self.preprocessor


# Shared model manager.
model_manager = ModelManager()