from datetime import datetime
from extensions.database import db

class NetworkEvent(db.Model):
    __tablename__ = "network_events"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    source_ip = db.Column(db.String(64))
    destination_ip = db.Column(db.String(64))
    source_port = db.Column(db.Integer)
    destination_port = db.Column(db.Integer)
    protocol = db.Column(db.String(20))
    packet_count = db.Column(db.Integer, default=0)
    byte_count = db.Column(db.Integer, default=0)
    duration = db.Column(db.Float, default=0)
    prediction = db.Column(db.String(80))
    confidence = db.Column(db.Float)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
