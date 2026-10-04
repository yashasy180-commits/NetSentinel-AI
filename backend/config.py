import os
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv


# ---------------------------------------------------------
# Load environment variables
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

# .env is located at:
# C:\NetSentinel-AI\.env
PROJECT_ROOT = BASE_DIR.parent
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)


# ---------------------------------------------------------
# Helper: build a reliable SQLite database URL
# ---------------------------------------------------------

def build_database_url():
    configured_url = os.getenv(
        "DATABASE_URL",
        "sqlite:///database/netsentinel.db",
    ).strip()

    # PostgreSQL / MySQL / other external database URLs
    # are returned unchanged.
    if not configured_url.startswith("sqlite:///"):
        return configured_url

    # Remove sqlite:/// from:
    # sqlite:///database/netsentinel.db
    relative_path = configured_url[len("sqlite:///"):]

    # If an absolute Windows path was supplied, normalize it.
    if len(relative_path) >= 2 and relative_path[1] == ":":
        database_path = Path(relative_path).resolve()
    else:
        # Resolve relative SQLite paths from the backend folder.
        database_path = (BASE_DIR / relative_path).resolve()

    # Make sure the parent directory exists.
    database_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert Windows path to SQLite-compatible URI.
    return f"sqlite:///{database_path.as_posix()}"


# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------

class Config:

    SECRET_KEY = os.getenv("SECRET_KEY")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")

    if not SECRET_KEY or SECRET_KEY == "your-secret-key-here":
        raise RuntimeError(
            "SECRET_KEY must be configured in the .env file."
        )

    if not JWT_SECRET_KEY or JWT_SECRET_KEY == "your-different-secret-key-here":
        raise RuntimeError(
            "JWT_SECRET_KEY must be configured in the .env file."
        )

    # Database
    SQLALCHEMY_DATABASE_URI = build_database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(
            os.getenv("JWT_ACCESS_TOKEN_MINUTES", "30")
        )
    )

    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        days=int(
            os.getenv("JWT_REFRESH_TOKEN_DAYS", "7")
        )
    )

    JWT_TOKEN_LOCATION = ["headers"]
    JWT_HEADER_NAME = "Authorization"
    JWT_HEADER_TYPE = "Bearer"

    # CORS
    CORS_ORIGINS = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173",
        ).split(",")
        if origin.strip()
    ]

    # Authentication
    PASSWORD_MIN_LENGTH = int(
        os.getenv("PASSWORD_MIN_LENGTH", "8")
    )

    LOGIN_RATE_LIMIT = os.getenv(
        "LOGIN_RATE_LIMIT",
        "5 per minute",
    )

    ENABLE_RATE_LIMITING = (
        os.getenv("ENABLE_RATE_LIMITING", "true").lower()
        == "true"
    )