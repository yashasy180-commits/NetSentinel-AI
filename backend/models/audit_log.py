from datetime import datetime, timezone

from extensions.database import db


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    action = db.Column(
        db.String(100),
        nullable=False,
        index=True,
    )

    resource = db.Column(
        db.String(100),
        nullable=True,
    )

    ip_address = db.Column(
        db.String(45),
        nullable=True,
    )

    user_agent = db.Column(
        db.String(500),
        nullable=True,
    )

    details = db.Column(
        db.Text,
        nullable=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )