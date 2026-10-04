import re

from flask import current_app


USERNAME_RE = re.compile(
    r"^[A-Za-z0-9_.-]{3,50}$"
)

EMAIL_RE = re.compile(
    r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
)


def validate_username(username: str) -> str | None:
    if not isinstance(username, str):
        return "Username is required."

    if not USERNAME_RE.fullmatch(username):
        return (
            "Username must be 3-50 characters and contain "
            "only letters, numbers, '.', '_' or '-'."
        )

    return None


def validate_email(email: str) -> str | None:
    if not isinstance(email, str):
        return "Email is required."

    if len(email) > 255:
        return "Email address is too long."

    if not EMAIL_RE.fullmatch(email):
        return "Enter a valid email address."

    return None


def validate_password(password: str) -> str | None:
    if not isinstance(password, str):
        return "Password is required."

    minimum = current_app.config[
        "PASSWORD_MIN_LENGTH"
    ]

    if len(password) < minimum:
        return (
            f"Password must contain at least "
            f"{minimum} characters."
        )

    if len(password) > 128:
        return (
            "Password must not exceed "
            "128 characters."
        )

    if not re.search(r"[A-Z]", password):
        return (
            "Password must contain at least "
            "one uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        return (
            "Password must contain at least "
            "one lowercase letter."
        )

    if not re.search(r"\d", password):
        return (
            "Password must contain at least "
            "one number."
        )

    if not re.search(
        r"[^A-Za-z0-9]",
        password,
    ):
        return (
            "Password must contain at least "
            "one special character."
        )

    return None