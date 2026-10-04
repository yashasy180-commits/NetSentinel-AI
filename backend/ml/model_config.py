"""
NetSentinel AI
Module 4 - Machine Learning Configuration
"""

from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

MODEL_DIR = BASE_DIR / "models"

MODEL_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

MODEL_PATH = MODEL_DIR / "intrusion_detection_model.joblib"

PREPROCESSOR_PATH = (
    MODEL_DIR / "network_preprocessor.joblib"
)

MODEL_METADATA_PATH = (
    MODEL_DIR / "model_metadata.joblib"
)


# Classification labels
BENIGN_LABEL = 0
INTRUSION_LABEL = 1

BENIGN_NAME = "BENIGN"
INTRUSION_NAME = "INTRUSION"


# Detection threshold
DEFAULT_THRESHOLD = 0.50


# Reproducibility
RANDOM_STATE = 42


# Random Forest configuration
N_ESTIMATORS = 200

MAX_DEPTH = 20

MIN_SAMPLES_SPLIT = 2

MIN_SAMPLES_LEAF = 1