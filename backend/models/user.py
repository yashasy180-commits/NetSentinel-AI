from datetime import datetime, timezone

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)

from extensions.database import db


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(
        db.Integer,
        primary_key=True,
    )

    username = db.Column(
        db.String(50),
        unique=True,
        nullable=False,
        index=True,
    )

    email = db.Column(
        db.String(255),
        unique=True,
        nullable=False,
        index=True,
    )

    password_hash = db.Column(
        db.String(255),
        nullable=False,
    )

    role = db.Column(
        db.String(20),
        nullable=False,
        default="ANALYST",
        index=True,
    )

    is_active = db.Column(
        db.Boolean,
        nullable=False,
        default=True,
        index=True,
    )

    created_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    updated_at = db.Column(
        db.DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    last_login_at = db.Column(
        db.DateTime(timezone=True),
        nullable=True,
    )

    # --------------------------------------------------------
    # Password handling
    # --------------------------------------------------------

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(
            password,
            method="scrypt",
        )

    def check_password(self, password: str) -> bool:
        return check_password_hash(
            self.password_hash,
            password,
        )

    # --------------------------------------------------------
    # Safe API representation
    # --------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": (
                self.created_at.isoformat()
                if self.created_at
                else None
            ),
            "updated_at": (
                self.updated_at.isoformat()
                if self.updated_at
                else None
            ),
            "last_login_at": (
                self.last_login_at.isoformat()
                if self.last_login_at
                else None
            ),
        }