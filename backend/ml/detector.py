"""
NetSentinel AI
Module 4 - Intrusion Detection Engine

Converts network flows into ML predictions and
security risk classifications.
"""

from __future__ import annotations

from typing import Any

from feature_engineering.feature_schema import (
    FEATURE_NAMES,
)
from feature_engineering.feature_extractor import (
    feature_extractor,
)

from ml.model_config import (
    BENIGN_LABEL,
    INTRUSION_LABEL,
    BENIGN_NAME,
    INTRUSION_NAME,
    DEFAULT_THRESHOLD,
)

from ml.model_manager import (
    model_manager,
)


class IntrusionDetector:
    """AI-powered network intrusion detector."""

    def __init__(
        self,
        threshold: float = DEFAULT_THRESHOLD,
    ) -> None:

        if not 0.0 < threshold < 1.0:
            raise ValueError(
                "Detection threshold must be between "
                "0 and 1."
            )

        self.threshold = threshold

    # =========================================================
    # Single Flow Detection
    # =========================================================

    def detect_flow(
        self,
        flow,
    ) -> dict[str, Any]:
        """
        Analyze one NetworkFlow object.
        """

        features = (
            feature_extractor.extract_from_flow(
                flow
            )
        )

        return self.detect_features(
            features
        )

    # =========================================================
    # Feature Detection
    # =========================================================

    def detect_features(
        self,
        features: dict,
    ) -> dict[str, Any]:
        """
        Analyze a single feature dictionary.
        """

        self._validate_features(
            features
        )

        predictions = model_manager.predict(
            [features]
        )

        probabilities = (
            model_manager.predict_probability(
                [features]
            )
        )

        model = model_manager.get_model()

        classes = list(
            model.classes_
        )

        prediction = int(
            predictions[0]
        )

        intrusion_probability = (
            self._get_intrusion_probability(
                classes,
                probabilities[0],
            )
        )

        classification = (
            self._classify(
                prediction,
                intrusion_probability,
            )
        )

        return {
            "prediction": classification[
                "prediction"
            ],
            "prediction_label": prediction,
            "probability": round(
                intrusion_probability,
                6,
            ),
            "confidence": round(
                classification[
                    "confidence"
                ],
                6,
            ),
            "risk_level": classification[
                "risk_level"
            ],
            "threshold": self.threshold,
            "features": features,
        }

    # =========================================================
    # Multiple Flow Detection
    # =========================================================

    def detect_flows(
        self,
        flows,
    ) -> list[dict[str, Any]]:
        """
        Analyze multiple NetworkFlow objects.
        """

        features = (
            feature_extractor.extract_from_flows(
                flows
            )
        )

        if not features:
            return []

        predictions = model_manager.predict(
            features
        )

        probabilities = (
            model_manager.predict_probability(
                features
            )
        )

        model = model_manager.get_model()

        classes = list(
            model.classes_
        )

        results = []

        for index, feature_row in enumerate(
            features
        ):

            prediction = int(
                predictions[index]
            )

            intrusion_probability = (
                self._get_intrusion_probability(
                    classes,
                    probabilities[index],
                )
            )

            classification = (
                self._classify(
                    prediction,
                    intrusion_probability,
                )
            )

            results.append(
                {
                    "prediction": classification[
                        "prediction"
                    ],
                    "prediction_label": prediction,
                    "probability": round(
                        intrusion_probability,
                        6,
                    ),
                    "confidence": round(
                        classification[
                            "confidence"
                        ],
                        6,
                    ),
                    "risk_level": classification[
                        "risk_level"
                    ],
                    "threshold": self.threshold,
                    "features": feature_row,
                }
            )

        return results

    # =========================================================
    # Probability
    # =========================================================

    def _get_intrusion_probability(
        self,
        classes: list,
        probabilities,
    ) -> float:
        """
        Extract the probability corresponding to
        the intrusion class.
        """

        if INTRUSION_LABEL in classes:

            index = classes.index(
                INTRUSION_LABEL
            )

            return float(
                probabilities[index]
            )

        return 0.0

    # =========================================================
    # Classification
    # =========================================================

    def _classify(
        self,
        prediction: int,
        probability: float,
    ) -> dict[str, Any]:
        """
        Convert model output into a security classification.
        """

        if (
            prediction == INTRUSION_LABEL
            or probability >= self.threshold
        ):

            prediction_name = (
                INTRUSION_NAME
            )

            confidence = probability

            risk_level = (
                self._risk_level(
                    probability
                )
            )

        else:

            prediction_name = (
                BENIGN_NAME
            )

            confidence = 1.0 - probability

            risk_level = "LOW"

        return {
            "prediction": prediction_name,
            "confidence": confidence,
            "risk_level": risk_level,
        }

    @staticmethod
    def _risk_level(
        probability: float,
    ) -> str:
        """
        Convert intrusion probability into a risk level.
        """

        if probability >= 0.90:
            return "CRITICAL"

        if probability >= 0.75:
            return "HIGH"

        if probability >= 0.50:
            return "MEDIUM"

        return "LOW"

    # =========================================================
    # Validation
    # =========================================================

    @staticmethod
    def _validate_features(
        features: dict,
    ) -> None:
        """
        Validate that all required ML features are present.
        """

        if not isinstance(
            features,
            dict,
        ):
            raise TypeError(
                "Features must be provided as a dictionary."
            )

        missing = [
            feature
            for feature in FEATURE_NAMES
            if feature not in features
        ]

        if missing:
            raise ValueError(
                "Missing required ML features: "
                + ", ".join(missing)
            )


# Shared detector instance.
intrusion_detector = IntrusionDetector()