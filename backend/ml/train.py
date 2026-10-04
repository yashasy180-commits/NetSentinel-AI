"""
NetSentinel AI
Module 4 - AI/ML Intrusion Detection Engine

Model training pipeline.

This module:
- Generates controlled synthetic training data for development
- Splits data into training and validation sets
- Fits the Module 3 preprocessing pipeline
- Trains a Random Forest intrusion-detection model
- Evaluates the model
- Saves the trained model
- Saves the fitted preprocessing artifact
- Saves model metadata

The generated traffic is synthetic and defensive.
No attack traffic is generated or transmitted.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
)
from sklearn.model_selection import train_test_split

from feature_engineering.preprocessing import (
    NetworkPreprocessor,
)

from ml.model_config import (
    DEFAULT_THRESHOLD,
    INTRUSION_LABEL,
    MODEL_DIR,
    MODEL_METADATA_PATH,
    MODEL_PATH,
    N_ESTIMATORS,
    MAX_DEPTH,
    MIN_SAMPLES_SPLIT,
    MIN_SAMPLES_LEAF,
    PREPROCESSOR_PATH,
    RANDOM_STATE,
)


# ============================================================
# Synthetic Dataset Generator
# ============================================================

def generate_training_dataset(
    benign_samples: int = 1500,
    intrusion_samples: int = 1500,
    random_state: int = RANDOM_STATE,
) -> pd.DataFrame:
    """
    Generate a controlled synthetic network-flow dataset.

    Label:
        0 = BENIGN
        1 = INTRUSION
    """

    rng = np.random.default_rng(
        random_state
    )

    # --------------------------------------------------------
    # BENIGN FLOWS
    # --------------------------------------------------------

    benign_duration = rng.uniform(
        1.0,
        120.0,
        benign_samples,
    )

    benign_packets = rng.integers(
        2,
        150,
        benign_samples,
    )

    benign_bytes = (
        benign_packets
        * rng.integers(
            40,
            1500,
            benign_samples,
        )
    )

    benign_protocol = rng.choice(
        [
            "TCP",
            "UDP",
        ],
        benign_samples,
    )

    benign_source_port = rng.choice(
        [
            1024,
            2048,
            3000,
            4000,
            50000,
            51000,
            52000,
            53000,
        ],
        benign_samples,
    )

    benign_destination_port = rng.choice(
        [
            53,
            80,
            443,
            22,
            123,
        ],
        benign_samples,
    )

    benign_forward_packets = (
        benign_packets
        * rng.uniform(
            0.55,
            0.90,
            benign_samples,
        )
    ).astype(int)

    benign_forward_packets = np.maximum(
        benign_forward_packets,
        1,
    )

    benign_reverse_packets = (
        benign_packets
        - benign_forward_packets
    )

    benign_forward_bytes = (
        benign_bytes
        * rng.uniform(
            0.55,
            0.90,
            benign_samples,
        )
    ).astype(int)

    benign_forward_bytes = np.minimum(
        benign_forward_bytes,
        benign_bytes,
    )

    benign_reverse_bytes = (
        benign_bytes
        - benign_forward_bytes
    )

    benign_syn = np.where(
        benign_protocol == "TCP",
        rng.integers(
            0,
            2,
            benign_samples,
        ),
        0,
    )

    benign_ack = np.where(
        benign_protocol == "TCP",
        rng.integers(
            0,
            20,
            benign_samples,
        ),
        0,
    )

    benign_fin = np.where(
        benign_protocol == "TCP",
        rng.integers(
            0,
            2,
            benign_samples,
        ),
        0,
    )

    benign_rst = np.where(
        benign_protocol == "TCP",
        rng.integers(
            0,
            2,
            benign_samples,
        ),
        0,
    )

    benign = pd.DataFrame(
        {
            "duration": benign_duration,
            "total_packets": benign_packets,
            "total_bytes": benign_bytes,
            "source_port": benign_source_port,
            "destination_port": benign_destination_port,
            "protocol": benign_protocol,
            "forward_packets": benign_forward_packets,
            "reverse_packets": benign_reverse_packets,
            "forward_bytes": benign_forward_bytes,
            "reverse_bytes": benign_reverse_bytes,
            "tcp_syn_count": benign_syn,
            "tcp_ack_count": benign_ack,
            "tcp_fin_count": benign_fin,
            "tcp_rst_count": benign_rst,
            "label": 0,
        }
    )

    benign["packets_per_second"] = (
        benign["total_packets"]
        / benign["duration"]
    )

    benign["bytes_per_second"] = (
        benign["total_bytes"]
        / benign["duration"]
    )

    # --------------------------------------------------------
    # INTRUSION-LIKE FLOWS
    # --------------------------------------------------------

    intrusion_duration = rng.uniform(
        0.01,
        8.0,
        intrusion_samples,
    )

    intrusion_packets = rng.integers(
        100,
        3000,
        intrusion_samples,
    )

    intrusion_bytes = (
        intrusion_packets
        * rng.integers(
            40,
            1000,
            intrusion_samples,
        )
    )

    intrusion_protocol = rng.choice(
        [
            "TCP",
            "UDP",
        ],
        intrusion_samples,
    )

    intrusion_source_port = rng.integers(
        1024,
        65535,
        intrusion_samples,
    )

    intrusion_destination_port = rng.choice(
        [
            21,
            22,
            23,
            25,
            53,
            80,
            110,
            139,
            443,
            445,
            3389,
        ],
        intrusion_samples,
    )

    intrusion_forward_packets = (
        intrusion_packets
        * rng.uniform(
            0.80,
            0.99,
            intrusion_samples,
        )
    ).astype(int)

    intrusion_forward_packets = np.maximum(
        intrusion_forward_packets,
        1,
    )

    intrusion_reverse_packets = (
        intrusion_packets
        - intrusion_forward_packets
    )

    intrusion_forward_bytes = (
        intrusion_bytes
        * rng.uniform(
            0.80,
            0.99,
            intrusion_samples,
        )
    ).astype(int)

    intrusion_forward_bytes = np.minimum(
        intrusion_forward_bytes,
        intrusion_bytes,
    )

    intrusion_reverse_bytes = (
        intrusion_bytes
        - intrusion_forward_bytes
    )

    intrusion_syn = np.where(
        intrusion_protocol == "TCP",
        rng.integers(
            3,
            80,
            intrusion_samples,
        ),
        0,
    )

    intrusion_ack = np.where(
        intrusion_protocol == "TCP",
        rng.integers(
            0,
            15,
            intrusion_samples,
        ),
        0,
    )

    intrusion_fin = np.where(
        intrusion_protocol == "TCP",
        rng.integers(
            0,
            2,
            intrusion_samples,
        ),
        0,
    )

    intrusion_rst = np.where(
        intrusion_protocol == "TCP",
        rng.integers(
            0,
            10,
            intrusion_samples,
        ),
        0,
    )

    intrusion = pd.DataFrame(
        {
            "duration": intrusion_duration,
            "total_packets": intrusion_packets,
            "total_bytes": intrusion_bytes,
            "source_port": intrusion_source_port,
            "destination_port": intrusion_destination_port,
            "protocol": intrusion_protocol,
            "forward_packets": intrusion_forward_packets,
            "reverse_packets": intrusion_reverse_packets,
            "forward_bytes": intrusion_forward_bytes,
            "reverse_bytes": intrusion_reverse_bytes,
            "tcp_syn_count": intrusion_syn,
            "tcp_ack_count": intrusion_ack,
            "tcp_fin_count": intrusion_fin,
            "tcp_rst_count": intrusion_rst,
            "label": INTRUSION_LABEL,
        }
    )

    intrusion["packets_per_second"] = (
        intrusion["total_packets"]
        / intrusion["duration"]
    )

    intrusion["bytes_per_second"] = (
        intrusion["total_bytes"]
        / intrusion["duration"]
    )

    # --------------------------------------------------------
    # Combine and shuffle
    # --------------------------------------------------------

    dataset = pd.concat(
        [
            benign,
            intrusion,
        ],
        ignore_index=True,
    )

    dataset = dataset.sample(
        frac=1.0,
        random_state=random_state,
    ).reset_index(drop=True)

    return dataset


# ============================================================
# Training
# ============================================================

def train_model(
    dataset: pd.DataFrame,
) -> tuple[
    RandomForestClassifier,
    NetworkPreprocessor,
    dict,
]:
    """
    Train and evaluate the intrusion-detection model.
    """

    if "label" not in dataset.columns:
        raise ValueError(
            "Training dataset must contain a 'label' column."
        )

    X = dataset.drop(
        columns=["label"]
    )

    y = dataset["label"]

    # --------------------------------------------------------
    # Train/test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    # --------------------------------------------------------
    # Preprocessing
    #
    # IMPORTANT:
    # Fit preprocessing ONLY on training data.
    # This prevents data leakage.
    # --------------------------------------------------------

    preprocessor = NetworkPreprocessor()

    X_train_processed = (
        preprocessor.fit_transform(
            X_train.to_dict(
                orient="records"
            )
        )
    )

    X_test_processed = (
        preprocessor.transform(
            X_test.to_dict(
                orient="records"
            )
        )
    )

    # --------------------------------------------------------
    # Model
    # --------------------------------------------------------

    model = RandomForestClassifier(
        n_estimators=N_ESTIMATORS,
        max_depth=MAX_DEPTH,
        min_samples_split=MIN_SAMPLES_SPLIT,
        min_samples_leaf=MIN_SAMPLES_LEAF,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    model.fit(
        X_train_processed,
        y_train,
    )

    # --------------------------------------------------------
    # Predictions
    # --------------------------------------------------------

    predictions = model.predict(
        X_test_processed
    )

    probabilities = model.predict_proba(
        X_test_processed
    )

    intrusion_index = list(
        model.classes_
    ).index(INTRUSION_LABEL)

    intrusion_probabilities = (
        probabilities[:, intrusion_index]
    )

    # --------------------------------------------------------
    # Metrics
    # --------------------------------------------------------

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    matrix = confusion_matrix(
        y_test,
        predictions,
    )

    report = classification_report(
        y_test,
        predictions,
        target_names=[
            "BENIGN",
            "INTRUSION",
        ],
        zero_division=0,
    )

    metadata = {
        "model_type": "RandomForestClassifier",
        "random_state": RANDOM_STATE,
        "n_estimators": N_ESTIMATORS,
        "max_depth": MAX_DEPTH,
        "training_samples": int(
            len(X_train)
        ),
        "testing_samples": int(
            len(X_test)
        ),
        "total_samples": int(
            len(dataset)
        ),
        "feature_count": int(
            X_train_processed.shape[1]
        ),
        "output_features": (
            preprocessor
            .get_output_feature_names()
        ),
        "classes": [
            int(value)
            for value in model.classes_
        ],
        "threshold": DEFAULT_THRESHOLD,
        "metrics": {
            "accuracy": float(
                accuracy
            ),
            "precision": float(
                precision
            ),
            "recall": float(
                recall
            ),
            "f1_score": float(
                f1
            ),
        },
        "confusion_matrix": matrix.tolist(),
        "classification_report": report,
        "mean_intrusion_probability": float(
            np.mean(
                intrusion_probabilities
            )
        ),
    }

    return (
        model,
        preprocessor,
        metadata,
    )


# ============================================================
# Save Artifacts
# ============================================================

def save_artifacts(
    model: RandomForestClassifier,
    preprocessor: NetworkPreprocessor,
    metadata: dict,
) -> None:
    """
    Save trained model, preprocessing pipeline,
    and metadata.
    """

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    joblib.dump(
        preprocessor,
        PREPROCESSOR_PATH,
    )

    # Save metadata both as joblib and readable JSON.
    joblib.dump(
        metadata,
        MODEL_METADATA_PATH,
    )

    json_path = (
        MODEL_METADATA_PATH
        .with_suffix(".json")
    )

    with open(
        json_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            metadata,
            file,
            indent=4,
        )


# ============================================================
# Main
# ============================================================

def main() -> None:
    """
    Execute the complete ML training pipeline.
    """

    print("=" * 60)
    print("NetSentinel AI - ML Training Pipeline")
    print("=" * 60)

    print("\n[1/5] Generating controlled training dataset...")

    dataset = generate_training_dataset(
        benign_samples=1500,
        intrusion_samples=1500,
    )

    print(
        f"Dataset shape: {dataset.shape}"
    )

    print(
        "Class distribution:",
        dataset["label"]
        .value_counts()
        .sort_index()
        .to_dict(),
    )

    print("\n[2/5] Training Random Forest model...")

    model, preprocessor, metadata = train_model(
        dataset
    )

    print("\n[3/5] Model evaluation complete.")

    metrics = metadata["metrics"]

    print(
        f"Accuracy : {metrics['accuracy']:.4f}"
    )

    print(
        f"Precision: {metrics['precision']:.4f}"
    )

    print(
        f"Recall   : {metrics['recall']:.4f}"
    )

    print(
        f"F1 Score : {metrics['f1_score']:.4f}"
    )

    print("\n[4/5] Classification report:")

    print(
        metadata["classification_report"]
    )

    print(
        "Confusion matrix:"
    )

    print(
        np.array(
            metadata["confusion_matrix"]
        )
    )

    print("\n[5/5] Saving ML artifacts...")

    save_artifacts(
        model,
        preprocessor,
        metadata,
    )

    print(
        f"\nModel saved to:\n{MODEL_PATH}"
    )

    print(
        f"\nPreprocessor saved to:\n"
        f"{PREPROCESSOR_PATH}"
    )

    print(
        f"\nMetadata saved to:\n"
        f"{MODEL_METADATA_PATH}"
    )

    print(
        "\nTraining pipeline completed successfully."
    )

    print("=" * 60)


if __name__ == "__main__":
    main()