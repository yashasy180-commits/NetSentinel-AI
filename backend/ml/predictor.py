from pathlib import Path
from ml.feature_extractor import extract_features, FEATURES

class Predictor:
    def __init__(self):
        self.model_path = Path(__file__).resolve().parents[1] / "models_ml" / "intrusion_model.joblib"
        self.model = None
        if self.model_path.exists():
            import joblib
            self.model = joblib.load(self.model_path)

    def predict(self, flow):
        if not isinstance(flow, dict):
            raise ValueError("JSON object required.")
        features = extract_features(flow)
        if self.model is None:
            return {
                "status": "model_not_trained",
                "prediction": "UNAVAILABLE",
                "confidence": 0.0,
                "features": features
            }
        values = [[features[f] for f in FEATURES]]
        prediction = self.model.predict(values)[0]
        confidence = float(max(self.model.predict_proba(values)[0])) if hasattr(self.model, "predict_proba") else 0.0
        return {
            "status": "ok",
            "prediction": str(prediction),
            "confidence": confidence,
            "features": features
        }
