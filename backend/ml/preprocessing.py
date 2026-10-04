from pathlib import Path
import joblib

def save_artifact(obj, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(obj, path)

def load_artifact(path):
    return joblib.load(path)
