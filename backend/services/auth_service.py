from datetime import datetime, timezone
from uuid import uuid4

from flask import current_app

from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
)

from extensions.database import db
from models.user import User
from security.audit import write_audit_log
from security.validators import (
    validate_email,
    validate_password,
    validate_username,
)


class AuthService:

    # ========================================================
    # REGISTER
    # ========================================================

    @staticmethod
    def register(
        username: str,
        email: str,
        password: str,
    ):

        username = username.strip()
        email = email.strip().lower()

        validation_errors = [
            error
            for error in (
                validate_username(username),
                validate_email(email),
                validate_password(password),
            )
            if error
        ]

        if validation_errors:
            return None, validation_errors

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:
            return None, [
                "Username is already registered."
            ]

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:
            return None, [
                "Email is already registered."
            ]

        # Public registration ALWAYS creates an
        # ANALYST account.
        #
        # ADMIN accounts are created separately
        # through create_admin.py.

        user = User(
            username=username,
            email=email,
            role="ANALYST",
            is_active=True,
        )

        user.set_password(password)

        try:
            db.session.add(user)

            db.session.flush()

            write_audit_log(
                action="USER_REGISTERED",
                user_id=user.id,
                resource="users",
                details={
                    "username": user.username,
                },
            )

            db.session.commit()

        except Exception:

            db.session.rollback()

            current_app.logger.exception(
                "User registration failed."
            )

            raise

        return user, []

    # ========================================================
    # LOGIN
    # ========================================================

    @staticmethod
    def authenticate(
        identifier: str,
        password: str,
    ):

        identifier = identifier.strip()

        user = User.query.filter(
            (
                User.email
                == identifier.lower()
            )
            |
            (
                User.username
                == identifier
            )
        ).first()

        if (
            user is None
            or not user.check_password(password)
        ):
            return (
                None,
                "Invalid username/email or password.",
            )

        if not user.is_active:
            return (
                None,
                (
                    "This account is inactive. "
                    "Contact an administrator."
                ),
            )

        user.last_login_at = (
            datetime.now(timezone.utc)
        )

        # Every login receives a unique session.
        session_id = str(uuid4())

        claims = {
            "role": user.role,
            "username": user.username,
            "session_id": session_id,
        }

        access_token = create_access_token(
            identity=str(user.id),
            additional_claims=claims,
        )

        refresh_token = create_refresh_token(
            identity=str(user.id),
            additional_claims=claims,
        )

        try:

            write_audit_log(
                action="USER_LOGIN",
                user_id=user.id,
                resource="auth",
                details={
                    "username": user.username,
                },
            )

            db.session.commit()

        except Exception:

            db.session.rollback()

            current_app.logger.exception(
                "Login audit logging failed."
            )

            raise

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user": user.to_dict(),
        }, None