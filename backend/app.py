"""
NetSentinel AI
Application Entry Point

Integrated modules:
1. Authentication & User Management
2. Network Traffic Collection
3. Feature Extraction & Preprocessing
4. AI/ML Intrusion Detection
5. Real-Time Threat Monitoring
6. Threat Detection & Alert Management
7. Security Analytics & Reporting
8. Admin Control & System Management
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from flask import Flask, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config

from extensions.database import db
from extensions.jwt import jwt
from extensions.socket import socketio

from models import register_models
from models.token_blocklist import TokenBlocklist

from routes import (
    auth_bp,
    user_bp,
    admin_bp,
    traffic_bp,
    monitoring_bp,
    alert_bp,
    analytics_bp,
    report_bp,
)


# =============================================================
# APPLICATION PATHS
# =============================================================

BASE_DIR = Path(__file__).resolve().parent

LOG_DIR = BASE_DIR / "logs"
DATABASE_DIR = BASE_DIR / "database"


# =============================================================
# LOGGING
# =============================================================

def configure_logging(app: Flask) -> None:
    """Configure application and rotating file logging."""

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    log_file = LOG_DIR / "netsentinel.log"

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | "
        "%(name)s | %(message)s"
    )

    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )

    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)

    app.logger.setLevel(logging.INFO)

    app.logger.addHandler(file_handler)

    logging.getLogger("werkzeug").addHandler(
        file_handler
    )

    app.logger.info(
        "NetSentinel AI logging initialized."
    )


# =============================================================
# APPLICATION FACTORY
# =============================================================

def create_app() -> Flask:
    """Create and configure the Flask application."""

    app = Flask(__name__)

    # ---------------------------------------------------------
    # Configuration
    # ---------------------------------------------------------

    app.config.from_object(Config)

    # ---------------------------------------------------------
    # Required directories
    # ---------------------------------------------------------

    LOG_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    DATABASE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ---------------------------------------------------------
    # Logging
    # ---------------------------------------------------------

    configure_logging(app)

    # ---------------------------------------------------------
    # Database
    # ---------------------------------------------------------

    db.init_app(app)

    register_models()

    # ---------------------------------------------------------
    # JWT
    # ---------------------------------------------------------

    jwt.init_app(app)

    # ---------------------------------------------------------
    # Socket.IO
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # CORS / Socket.IO origins
    #
    # Origins are controlled through CORS_ORIGINS in the
    # environment. Multiple origins can be comma-separated.
    # ---------------------------------------------------------

    allowed_origins = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:5173,http://localhost:5174",
        ).split(",")
        if origin.strip()
    ]

    socketio.init_app(
        app,
        cors_allowed_origins=allowed_origins,
        async_mode="threading",
    )

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": allowed_origins,
                "methods": [
                    "GET",
                    "POST",
                    "PUT",
                    "PATCH",
                    "DELETE",
                    "OPTIONS",
                ],
                "allow_headers": [
                    "Content-Type",
                    "Authorization",
                ],
                "expose_headers": [
                    "Content-Type",
                    "Authorization",
                ],
                "supports_credentials": True,
            }
        },
    )

    # ---------------------------------------------------------
    # Explicit CORS headers
    #
    # This guarantees that OPTIONS preflight requests receive
    # the correct headers even when Flask automatically handles
    # OPTIONS before reaching a route.
    # ---------------------------------------------------------

    @app.after_request
    def add_cors_headers(response):
        origin = None

        try:
            from flask import request

            request_origin = request.headers.get(
                "Origin"
            )

            if request_origin in allowed_origins:
                origin = request_origin

        except Exception:
            origin = None

        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Headers"] = (
                "Content-Type, Authorization"
            )
            response.headers["Access-Control-Allow-Methods"] = (
                "GET, POST, PUT, PATCH, DELETE, OPTIONS"
            )
            response.headers["Vary"] = "Origin"

        return response

    # ---------------------------------------------------------
    # Rate Limiting
    # ---------------------------------------------------------

    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri="memory://",
        default_limits=[],
    )

    limiter.init_app(app)

    # =========================================================
    # JWT TOKEN REVOCATION
    # =========================================================

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(
        jwt_header,
        jwt_payload,
    ):
        """
        Check whether the JWT or its session
        has been revoked.
        """

        try:
            jti = jwt_payload.get("jti")
            session_id = jwt_payload.get("session_id")

            # -------------------------------------------------
            # Individual token
            # -------------------------------------------------

            if jti:
                revoked_token = (
                    db.session
                    .query(TokenBlocklist)
                    .filter_by(jti=jti)
                    .first()
                )

                if revoked_token is not None:
                    return True

            # -------------------------------------------------
            # Entire session
            # -------------------------------------------------

            if session_id:
                revoked_session = (
                    db.session
                    .query(TokenBlocklist)
                    .filter_by(
                        session_id=session_id
                    )
                    .first()
                )

                if revoked_session is not None:
                    return True

            return False

        except Exception:
            app.logger.exception(
                "JWT blocklist verification failed."
            )

            # Fail closed
            return True

    # =========================================================
    # JWT ERROR HANDLERS
    # =========================================================

    @jwt.revoked_token_loader
    def revoked_token_callback(
        jwt_header,
        jwt_payload,
    ):
        return jsonify(
            {
                "success": False,
                "message": "Token has been revoked.",
            }
        ), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        return jsonify(
            {
                "success": False,
                "message": "Invalid authentication token.",
            }
        ), 401

    @jwt.expired_token_loader
    def expired_token_callback(
        jwt_header,
        jwt_payload,
    ):
        return jsonify(
            {
                "success": False,
                "message": "Authentication token has expired.",
            }
        ), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify(
            {
                "success": False,
                "message": "Authentication token is required.",
            }
        ), 401

    @jwt.needs_fresh_token_loader
    def fresh_token_required_callback(
        jwt_header,
        jwt_payload,
    ):
        return jsonify(
            {
                "success": False,
                "message": "A fresh authentication token is required.",
            }
        ), 401

    # =========================================================
    # REGISTER BLUEPRINTS
    # =========================================================

    # Module 1
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)

    # Module 2
    app.register_blueprint(traffic_bp)

    # Module 5
    app.register_blueprint(monitoring_bp)

    # Module 6
    app.register_blueprint(alert_bp)

    # Module 7
    
    app.register_blueprint(analytics_bp)

    
    app.register_blueprint(report_bp)

    # =========================================================
    # HEALTH CHECK
    # =========================================================

    @app.get("/api/health")
    def health_check():
        return jsonify(
            {
                "success": True,
                "service": "NetSentinel AI",
                "status": "healthy",
            }
        ), 200

    # =========================================================
    # ERROR HANDLERS
    # =========================================================

    @app.errorhandler(404)
    def not_found(error):
        return jsonify(
            {
                "success": False,
                "message": "Requested resource was not found.",
            }
        ), 404

    @app.errorhandler(405)
    def method_not_allowed(error):
        return jsonify(
            {
                "success": False,
                "message": (
                    "HTTP method is not allowed "
                    "for this endpoint."
                ),
            }
        ), 405

    @app.errorhandler(429)
    def rate_limit_exceeded(error):
        return jsonify(
            {
                "success": False,
                "message": (
                    "Too many requests. "
                    "Please try again later."
                ),
            }
        ), 429

    @app.errorhandler(500)
    def internal_server_error(error):
        app.logger.exception(
            "Unhandled application error."
        )

        return jsonify(
            {
                "success": False,
                "message": "Internal server error.",
            }
        ), 500

    # =========================================================
    # DATABASE INITIALIZATION
    # =========================================================

    with app.app_context():

        try:
            db.create_all()

            app.logger.info(
                "Database tables verified."
            )

        except Exception:
            app.logger.exception(
                "Database initialization failed."
            )

            raise

    # =========================================================
    # APPLICATION READY
    # =========================================================

    app.logger.info(
        "NetSentinel AI application created."
    )

    return app


# =============================================================
# APPLICATION INSTANCE
# =============================================================

app = create_app()


# =============================================================
# DEVELOPMENT SERVER
# =============================================================

if __name__ == "__main__":

    app.logger.info(
        "Starting NetSentinel AI server."
    )

    socketio.run(
        app,
        host="127.0.0.1",
        port=5000,
        debug=False,
        allow_unsafe_werkzeug=True,
    )


