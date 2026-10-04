from datetime import datetime, timezone

from extensions.database import db


class TokenBlocklist(db.Model):
    __tablename__ = "token_blocklist"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    jti = db.Column(
        db.String(36),
        unique=True,
        nullable=False,
        index=True,
    )

    session_id = db.Column(
        db.String(36),
        nullable=False,
        index=True,
    )

    token_type = db.Column(
        db.String(20),
        nullable=False,
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey(
            "users.id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    revoked_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )