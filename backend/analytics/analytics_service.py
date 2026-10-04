"""
NetSentinel AI
Module 7 - Security Analytics & Reporting

Provides aggregated security analytics using
persisted alert data.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy import func

from extensions.database import db
from models.alert import Alert

from analytics.analytics_config import (
    DEFAULT_ANALYTICS_LIMIT,
    MAX_ANALYTICS_LIMIT,
    TIMELINE_DEFAULT_HOURS,
    TIMELINE_MAX_HOURS,
)


class AnalyticsService:
    """Generate security analytics from alert data."""

    # =========================================================
    # Helpers
    # =========================================================

    @staticmethod
    def _normalize_limit(value) -> int:
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = DEFAULT_ANALYTICS_LIMIT

        return max(
            1,
            min(
                value,
                MAX_ANALYTICS_LIMIT,
            ),
        )

    @staticmethod
    def _normalize_hours(value) -> int:
        try:
            value = int(value)
        except (TypeError, ValueError):
            value = TIMELINE_DEFAULT_HOURS

        return max(
            1,
            min(
                value,
                TIMELINE_MAX_HOURS,
            ),
        )

    # =========================================================
    # Overview
    # =========================================================

    @classmethod
    def get_overview(cls) -> dict:
        """Return high-level security statistics."""

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
            "total_alerts": total,
            "active_alerts": (
                open_count + acknowledged_count
            ),
            "open_alerts": open_count,
            "acknowledged_alerts": acknowledged_count,
            "resolved_alerts": resolved_count,
            "severity": {
                "critical": critical_count,
                "high": high_count,
                "medium": medium_count,
                "low": low_count,
            },
        }

    # =========================================================
    # Severity Analytics
    # =========================================================

    @classmethod
    def get_severity_distribution(cls) -> dict:
        """Return alert distribution by severity."""

        rows = (
            db.session.query(
                Alert.severity,
                func.count(Alert.id),
            )
            .group_by(Alert.severity)
            .all()
        )

        distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }

        for severity, count in rows:

            if severity in distribution:
                distribution[severity] = int(count)

        return distribution

    # =========================================================
    # Status Analytics
    # =========================================================

    @classmethod
    def get_status_distribution(cls) -> dict:
        """Return alert distribution by workflow status."""

        rows = (
            db.session.query(
                Alert.status,
                func.count(Alert.id),
            )
            .group_by(Alert.status)
            .all()
        )

        distribution = {
            "OPEN": 0,
            "ACKNOWLEDGED": 0,
            "RESOLVED": 0,
        }

        for status, count in rows:

            if status in distribution:
                distribution[status] = int(count)

        return distribution

    # =========================================================
    # Protocol Analytics
    # =========================================================

    @classmethod
    def get_protocol_distribution(cls) -> dict:
        """Return detected alerts grouped by protocol."""

        rows = (
            db.session.query(
                Alert.protocol,
                func.count(Alert.id),
            )
            .filter(
                Alert.protocol.isnot(None)
            )
            .group_by(Alert.protocol)
            .order_by(
                func.count(Alert.id).desc()
            )
            .all()
        )

        return {
            str(protocol): int(count)
            for protocol, count in rows
        }

    # =========================================================
    # Top Source IPs
    # =========================================================

    @classmethod
    def get_top_source_ips(
        cls,
        limit=10,
    ) -> list[dict]:
        """Return source IPs with the most alerts."""

        limit = cls._normalize_limit(limit)

        rows = (
            db.session.query(
                Alert.source_ip,
                func.count(Alert.id).label(
                    "alert_count"
                ),
            )
            .filter(
                Alert.source_ip.isnot(None)
            )
            .group_by(Alert.source_ip)
            .order_by(
                func.count(Alert.id).desc()
            )
            .limit(limit)
            .all()
        )

        return [
            {
                "source_ip": str(source_ip),
                "alert_count": int(alert_count),
            }
            for source_ip, alert_count in rows
        ]

    # =========================================================
    # Top Destination IPs
    # =========================================================

    @classmethod
    def get_top_destination_ips(
        cls,
        limit=10,
    ) -> list[dict]:
        """Return destination IPs with the most alerts."""

        limit = cls._normalize_limit(limit)

        rows = (
            db.session.query(
                Alert.destination_ip,
                func.count(Alert.id).label(
                    "alert_count"
                ),
            )
            .filter(
                Alert.destination_ip.isnot(None)
            )
            .group_by(Alert.destination_ip)
            .order_by(
                func.count(Alert.id).desc()
            )
            .limit(limit)
            .all()
        )

        return [
            {
                "destination_ip": str(
                    destination_ip
                ),
                "alert_count": int(
                    alert_count
                ),
            }
            for destination_ip, alert_count in rows
        ]

    # =========================================================
    # Threat History
    # =========================================================

    @classmethod
    def get_threats(
        cls,
        limit=100,
        severity=None,
        status=None,
    ) -> list[dict]:
        """Return recent threat records."""

        limit = cls._normalize_limit(limit)

        query = Alert.query

        if severity:
            query = query.filter(
                Alert.severity == severity.upper()
            )

        if status:
            query = query.filter(
                Alert.status == status.upper()
            )

        alerts = (
            query
            .order_by(
                Alert.created_at.desc()
            )
            .limit(limit)
            .all()
        )

        return [
            alert.to_dict()
            for alert in alerts
        ]

    # =========================================================
    # Timeline
    # =========================================================

    @classmethod
    def get_timeline(
        cls,
        hours=TIMELINE_DEFAULT_HOURS,
    ) -> list[dict]:
        """
        Return hourly alert counts for the
        requested time window.
        """

        hours = cls._normalize_hours(hours)

        now = datetime.now(timezone.utc)

        start_time = (
            now - timedelta(hours=hours)
        )

        alerts = (
            Alert.query
            .filter(
                Alert.created_at >= start_time
            )
            .order_by(
                Alert.created_at.asc()
            )
            .all()
        )

        buckets: dict[str, dict] = {}

        for index in range(hours):

            bucket_time = (
                start_time
                + timedelta(hours=index)
            )

            bucket_time = bucket_time.replace(
                minute=0,
                second=0,
                microsecond=0,
            )

            key = bucket_time.isoformat()

            buckets[key] = {
                "timestamp": key,
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            }

        for alert in alerts:

            created = alert.created_at

            if created is None:
                continue

            if created.tzinfo is None:

                created = created.replace(
                    tzinfo=timezone.utc
                )

            bucket_time = created.replace(
                minute=0,
                second=0,
                microsecond=0,
            )

            key = bucket_time.isoformat()

            if key not in buckets:
                continue

            buckets[key]["total"] += 1

            severity = (
                str(
                    alert.severity
                    or "LOW"
                ).lower()
            )

            if severity in (
                "critical",
                "high",
                "medium",
                "low",
            ):
                buckets[key][
                    severity
                ] += 1

        return list(
            buckets.values()
        )

    # =========================================================
    # Complete Analytics
    # =========================================================

    @classmethod
    def get_dashboard_data(
        cls,
        timeline_hours=24,
        top_limit=10,
    ) -> dict:
        """Return a complete dashboard analytics payload."""

        return {
            "overview": cls.get_overview(),
            "severity_distribution": (
                cls.get_severity_distribution()
            ),
            "status_distribution": (
                cls.get_status_distribution()
            ),
            "protocol_distribution": (
                cls.get_protocol_distribution()
            ),
            "top_source_ips": (
                cls.get_top_source_ips(
                    top_limit
                )
            ),
            "top_destination_ips": (
                cls.get_top_destination_ips(
                    top_limit
                )
            ),
            "timeline": cls.get_timeline(
                timeline_hours
            ),
        }


analytics_service = AnalyticsService()