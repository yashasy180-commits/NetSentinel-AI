"""
NetSentinel AI
Module 3 - Feature Preprocessing

Provides a consistent preprocessing pipeline for the
network intrusion detection machine-learning system.

Responsibilities:
- Validate feature dictionaries
- Handle missing values
- Encode categorical protocol values
- Scale numerical features
- Maintain consistent feature ordering
- Save/load preprocessing artifacts
- Keep training and inference preprocessing identical
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

import joblib
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

from feature_engineering.feature_schema import (
    CATEGORICAL_FEATURES,
    FEATURE_NAMES,
    NUMERIC_FEATURES,
)


class NetworkPreprocessor:
    """
    Preprocessing pipeline for network-flow ML features.

    The same fitted preprocessor must be used during both
    model training and model inference.
    """

    def __init__(self) -> None:

        self.pipeline: ColumnTransformer | None = None

        self.feature_names = FEATURE_NAMES.copy()

        self.numeric_features = NUMERIC_FEATURES.copy()

        self.categorical_features = (
            CATEGORICAL_FEATURES.copy()
        )

        self.is_fitted = False

    # =========================================================
    # Pipeline Construction
    # =========================================================

    def _build_pipeline(self) -> ColumnTransformer:
        """
        Build the sklearn preprocessing pipeline.
        """

        numeric_pipeline = Pipeline(
            steps=[
                (
                    "imputer",
                    SimpleImputer(
                        strategy="median"
                    ),
                ),
                (
                    "scaler",
                    StandardScaler(),
                ),
            ]
        )

        categorical_pipeline = Pipeline(
            steps=[
                (
                    "imputer",
                    SimpleImputer(
                        strategy="most_frequent"
                    ),
                ),
                (
                    "encoder",
                    OneHotEncoder(
                        handle_unknown="ignore",
                        sparse_output=False,
                    ),
                ),
            ]
        )

        return ColumnTransformer(
            transformers=[
                (
                    "numeric",
                    numeric_pipeline,
                    self.numeric_features,
                ),
                (
                    "categorical",
                    categorical_pipeline,
                    self.categorical_features,
                ),
            ],
            remainder="drop",
        )

    # =========================================================
    # Data Preparation
    # =========================================================

    def _prepare_dataframe(
        self,
        feature_rows: Iterable[dict],
    ) -> pd.DataFrame:
        """
        Convert feature dictionaries into a DataFrame with
        the exact expected feature schema.
        """

        rows = list(feature_rows)

        if not rows:
            raise ValueError(
                "At least one feature row is required."
            )

        dataframe = pd.DataFrame(rows)

        # Add missing expected columns.
        for feature in self.feature_names:

            if feature not in dataframe.columns:
                dataframe[feature] = None

        # Keep only the standardized feature columns
        # and preserve their exact order.
        dataframe = dataframe[
            self.feature_names
        ].copy()

        return dataframe

    # =========================================================
    # Fit
    # =========================================================

    def fit(
        self,
        feature_rows: Iterable[dict],
    ) -> "NetworkPreprocessor":
        """
        Fit the preprocessing pipeline using training data.
        """

        dataframe = self._prepare_dataframe(
            feature_rows
        )

        self.pipeline = self._build_pipeline()

        self.pipeline.fit(dataframe)

        self.is_fitted = True

        return self

    # =========================================================
    # Transform
    # =========================================================

    def transform(
        self,
        feature_rows: Iterable[dict],
    ):
        """
        Transform feature rows using the fitted pipeline.

        The pipeline must already be fitted.
        """

        if not self.is_fitted or self.pipeline is None:

            raise RuntimeError(
                "Preprocessor has not been fitted. "
                "Call fit() before transform()."
            )

        dataframe = self._prepare_dataframe(
            feature_rows
        )

        transformed = self.pipeline.transform(
            dataframe
        )

        return transformed

    # =========================================================
    # Fit + Transform
    # =========================================================

    def fit_transform(
        self,
        feature_rows: Iterable[dict],
    ):
        """
        Fit the preprocessing pipeline and transform
        the same dataset.
        """

        dataframe = self._prepare_dataframe(
            feature_rows
        )

        self.pipeline = self._build_pipeline()

        transformed = self.pipeline.fit_transform(
            dataframe
        )

        self.is_fitted = True

        return transformed

    # =========================================================
    # Feature Names
    # =========================================================

    def get_output_feature_names(self) -> list[str]:
        """
        Return the feature names produced by the fitted
        preprocessing pipeline.
        """

        if not self.is_fitted or self.pipeline is None:

            raise RuntimeError(
                "Preprocessor has not been fitted."
            )

        try:

            names = (
                self.pipeline
                .get_feature_names_out()
            )

            return [
                str(name)
                for name in names
            ]

        except Exception:

            return []

    # =========================================================
    # Save
    # =========================================================

    def save(
        self,
        file_path: str | Path,
    ) -> Path:
        """
        Save the fitted preprocessing artifact.
        """

        if not self.is_fitted:

            raise RuntimeError(
                "Cannot save an unfitted preprocessor."
            )

        path = Path(file_path)

        path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        joblib.dump(
            self,
            path,
        )

        return path

    # =========================================================
    # Load
    # =========================================================

    @classmethod
    def load(
        cls,
        file_path: str | Path,
    ) -> "NetworkPreprocessor":
        """
        Load a previously saved preprocessing artifact.
        """

        path = Path(file_path)

        if not path.exists():

            raise FileNotFoundError(
                f"Preprocessor artifact not found: {path}"
            )

        preprocessor = joblib.load(path)

        if not isinstance(
            preprocessor,
            cls,
        ):

            raise TypeError(
                "Invalid preprocessing artifact."
            )

        return preprocessor


# Shared instance for application-level use.
preprocessor = NetworkPreprocessor()