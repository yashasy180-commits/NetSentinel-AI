from flask import Blueprint, request, jsonify
from ml.predictor import Predictor

detection_bp = Blueprint("detection", __name__)
predictor = Predictor()

@detection_bp.post("/predict")
def predict():
    data = request.get_json(silent=True) or {}
    try:
        result = predictor.predict(data)
        return jsonify(result)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        return jsonify({"error": "prediction failed"}), 500

@detection_bp.get("/recent")
def recent():
    return jsonify({"detections": []})
