from datetime import datetime
from extensions.database import db

class ModelRegistry(db.Model):
    __tablename__ = "model_registry"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    version = db.Column(db.String(50), nullable=False)
    algorithm = db.Column(db.String(80))
    accuracy = db.Column(db.Float)
    precision = db.Column(db.Float)
    recall = db.Column(db.Float)
    f1_score = db.Column(db.Float)
    artifact_path = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
