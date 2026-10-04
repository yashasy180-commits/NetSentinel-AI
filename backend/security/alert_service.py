"""
NetSentinel AI
Module 6 - Threat Detection & Alert Management

Service layer responsible for creating, retrieving,
acknowledging, and resolving security alerts.
"""

from __future__ import annotations

from datetime import datetime, timezone

from extensions.database import db
from models.alert import Alert


class AlertService:
    """Business logic for security alert management."""

    SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    STATUSES = {"OPEN", "ACKNOWLEDGED", "RESOLVED"}

    @staticmethod
    def normalize_probability(value) -> float:
        """Keep probability within the 0.0-1.0 range."""
        try:
            value = float(value)
        except (TypeError, ValueError):
            return 0.0

        return max(0.0, min(1.0, value))

    @classmethod
    def calculate_severity(
        cls,
        probability: float,
        prediction: str | None = None,
    ) -> str:
        """Convert an AI intrusion probability into alert severity."""

        probability = cls.normalize_probability(probability)

        if prediction != "INTRUSION":
            return "LOW"

        if probability >= 0.90:
            return "CRITICAL"

        if probability >= 0.75:
            return "HIGH"

        if probability >= 0.50:
            return "MEDIUM"

        return "LOW"

    @classmethod
    def create_alert(
        cls,
        detection: dict,
        source_ip: str | None = None,
        destination_ip: str | None = None,
    ) -> Alert | None:
        """
        Create an alert from an AI detection result.

        Only INTRUSION predictions are persisted.
        """

        if not isinstance(detection, dict):
            raise ValueError("Detection must be a dictionary.")

        prediction = str(
            detection.get("prediction", "")
        ).upper()

        if prediction != "INTRUSION":
            return None

        probability = cls.normalize_probability(
            detection.get("probability", 0.0)
        )

        confidence = cls.normalize_probability(
            detection.get("confidence", probability)
        )

        features = detection.get("features") or {}

        severity = cls.calculate_severity(
            probability=probability,
            prediction=prediction,
        )

        alert = Alert(
            alert_type="AI_INTRUSION_DETECTION",
            title=f"{severity} network intrusion detected",
            description=(
                "The AI intrusion detection engine identified "
                "network traffic matching an intrusion pattern."
            ),
            severity=severity,
            confidence=confidence,
            probability=probability,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=features.get("source_port"),
            destination_port=features.get("destination_port"),
            protocol=features.get("protocol"),
            status="OPEN",
            detection_data={
                "prediction": prediction,
                "prediction_label": detection.get("prediction_label"),
                "risk_level": detection.get("risk_level"),
                "threshold": detection.get("threshold"),
                "features": features,
            },
        )

        db.session.add(alert)
        db.session.commit()

        return alert

    @staticmethod
    def get_alert(alert_id: int) -> Alert | None:
        """Retrieve one alert."""
        return db.session.get(Alert, alert_id)

    @staticmethod
    def get_alerts(
        status: str | None = None,
        severity: str | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        """Retrieve alerts with optional filters."""

        query = Alert.query

        if status:
            query = query.filter(
                Alert.status == status.upper()
            )

        if severity:
            query = query.filter(
                Alert.severity == severity.upper()
            )

        try:
            limit = int(limit)
        except (TypeError, ValueError):
            limit = 100

        limit = max(1, min(limit, 500))

        return (
            query
            .order_by(Alert.created_at.desc())
            .limit(limit)
            .all()
        )

    @staticmethod
    def acknowledge_alert(
        alert_id: int,
        user_id: int,
    ) -> Alert | None:
        """Mark an alert as acknowledged."""

        alert = db.session.get(Alert, alert_id)

        if alert is None:
            return None

        if alert.status == "RESOLVED":
            raise ValueError(
                "A resolved alert cannot be acknowledged."
            )

        alert.status = "ACKNOWLEDGED"
        alert.acknowledged_by = user_id
        alert.acknowledged_at = datetime.now(timezone.utc)

        db.session.commit()

        return alert

    @staticmethod
    def resolve_alert(
        alert_id: int,
        user_id: int,
    ) -> Alert | None:
        """Mark an alert as resolved."""

        alert = db.session.get(Alert, alert_id)

        if alert is None:
            return None

        alert.status = "RESOLVED"
        alert.resolved_by = user_id
        alert.resolved_at = datetime.now(timezone.utc)

        db.session.commit()

        return alert

    @staticmethod
    def get_statistics() -> dict:
        """Return alert statistics."""

        total = Alert.query.count()

        open_count = Alert.query.filter_by(
            status="OPEN"
        ).count()

        acknowledged_count = Alert.query.filter_by(
            status="ACKNOWLEDGED"
        ).count()

        resolved_count = Alert.query.filter_by(
            status="RESOLVED"
        ).count()

        critical_count = Alert.query.filter_by(
            severity="CRITICAL"
        ).count()

        high_count = Alert.query.filter_by(
            severity="HIGH"
        ).count()

        medium_count = Alert.query.filter_by(
            severity="MEDIUM"
        ).count()

        low_count = Alert.query.filter_by(
            severity="LOW"
        ).count()

        return {
            "total": total,
            "open": open_count,
            "acknowledged": acknowledged_count,
            "resolved": resolved_count,
            "by_severity": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            },
        }


alert_service = AlertService()