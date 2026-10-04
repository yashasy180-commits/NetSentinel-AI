"""
NetSentinel AI
Module 8 - Admin Control & System Management

Administrator-only routes for:
- User administration
- User activation/deactivation
- User role management
- Audit log management
- System status monitoring
"""

from __future__ import annotations

import json

from flask import (
    Blueprint,
    jsonify,
    request,
)

from flask_jwt_extended import (
    get_jwt_identity,
    jwt_required,
)

from extensions.database import db

from models.user import User
from models.audit_log import AuditLog

from security.audit import write_audit_log
from security.authorization import roles_required

from ml.model_manager import model_manager
from monitoring.monitor import network_monitor
from services.alert_service import alert_service


admin_bp = Blueprint(
    "admin",
    __name__,
    url_prefix="/api/admin",
)


# ============================================================
# USER MANAGEMENT
# ============================================================

@admin_bp.get("/users")
@jwt_required()
@roles_required("ADMIN")
def list_users():
    """
    Return all registered users.

    Administrator access only.
    """

    users = (
        User.query
        .order_by(
            User.created_at.desc()
        )
        .all()
    )

    return jsonify({
        "success": True,
        "users": [
            user.to_dict()
            for user in users
        ],
    }), 200


# ============================================================
# ACTIVATE / DEACTIVATE USER
# ============================================================

@admin_bp.patch(
    "/users/<int:user_id>/status"
)
@jwt_required()
@roles_required("ADMIN")
def update_user_status(
    user_id: int,
):
    """
    Activate or deactivate a user account.
    """

    payload = request.get_json(
        silent=True
    )

    if (
        not isinstance(payload, dict)
        or not isinstance(
            payload.get("is_active"),
            bool,
        )
    ):
        return jsonify({
            "success": False,
            "message": (
                "is_active must be a boolean."
            ),
        }), 400

    user = db.session.get(
        User,
        user_id,
    )

    if user is None:
        return jsonify({
            "success": False,
            "message": "User not found.",
        }), 404

    current_user_id = int(
        get_jwt_identity()
    )

    # ---------------------------------------------------------
    # Prevent administrator self-deactivation
    # ---------------------------------------------------------

    if (
        user.id == current_user_id
        and payload["is_active"] is False
    ):
        return jsonify({
            "success": False,
            "message": (
                "You cannot deactivate "
                "your own account."
            ),
        }), 400

    user.is_active = (
        payload["is_active"]
    )

    try:

        write_audit_log(
            action="USER_STATUS_CHANGED",
            user_id=current_user_id,
            resource=f"users/{user.id}",
            details={
                "target_user_id": user.id,
                "is_active": user.is_active,
            },
        )

        db.session.commit()

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to update "
                "account status."
            ),
        }), 500

    return jsonify({
        "success": True,
        "message": (
            "User status updated."
        ),
        "user": user.to_dict(),
    }), 200


# ============================================================
# ROLE MANAGEMENT
# ============================================================

@admin_bp.patch(
    "/users/<int:user_id>/role"
)
@jwt_required()
@roles_required("ADMIN")
def update_user_role(
    user_id: int,
):
    """
    Change a user's administrative role.

    Supported roles:
        ADMIN
        ANALYST

    Administrators cannot change their own role.
    """

    payload = request.get_json(
        silent=True
    )

    if not isinstance(
        payload,
        dict,
    ):
        return jsonify({
            "success": False,
            "message": (
                "JSON request body "
                "must be an object."
            ),
        }), 400

    role = payload.get(
        "role"
    )

    if not isinstance(
        role,
        str,
    ):
        return jsonify({
            "success": False,
            "message": (
                "role must be a string."
            ),
        }), 400

    role = role.strip().upper()

    allowed_roles = {
        "ADMIN",
        "ANALYST",
    }

    if role not in allowed_roles:
        return jsonify({
            "success": False,
            "message": (
                "Invalid role. "
                "Allowed roles are "
                "ADMIN and ANALYST."
            ),
        }), 400

    user = db.session.get(
        User,
        user_id,
    )

    if user is None:
        return jsonify({
            "success": False,
            "message": "User not found.",
        }), 404

    current_user_id = int(
        get_jwt_identity()
    )

    # ---------------------------------------------------------
    # Prevent self-role modification
    # ---------------------------------------------------------

    if user.id == current_user_id:
        return jsonify({
            "success": False,
            "message": (
                "You cannot change "
                "your own role."
            ),
        }), 400

    # ---------------------------------------------------------
    # No-op protection
    # ---------------------------------------------------------

    if user.role == role:
        return jsonify({
            "success": True,
            "message": (
                "User already has "
                f"the {role} role."
            ),
            "user": user.to_dict(),
        }), 200

    old_role = user.role

    user.role = role

    try:

        write_audit_log(
            action="USER_ROLE_CHANGED",
            user_id=current_user_id,
            resource=f"users/{user.id}",
            details={
                "target_user_id": user.id,
                "old_role": old_role,
                "new_role": role,
            },
        )

        db.session.commit()

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to update "
                "user role."
            ),
        }), 500

    return jsonify({
        "success": True,
        "message": (
            "User role updated."
        ),
        "user": user.to_dict(),
    }), 200


# ============================================================
# AUDIT LOG MANAGEMENT
# ============================================================

@admin_bp.get("/audit-logs")
@jwt_required()
@roles_required("ADMIN")
def list_audit_logs():
    """
    Return paginated audit logs for administrators.

    Optional query parameters:

        page
            Page number.
            Default: 1

        per_page
            Number of records per page.
            Default: 25
            Maximum: 100

        action
            Filter by exact audit action.

        user_id
            Filter by user ID.
    """

    # ---------------------------------------------------------
    # Pagination validation
    # ---------------------------------------------------------

    try:

        page = int(
            request.args.get(
                "page",
                1,
            )
        )

        per_page = int(
            request.args.get(
                "per_page",
                25,
            )
        )

    except (
        TypeError,
        ValueError,
    ):

        return jsonify({
            "success": False,
            "message": (
                "page and per_page "
                "must be integers."
            ),
        }), 400

    if page < 1:

        return jsonify({
            "success": False,
            "message": (
                "page must be greater "
                "than or equal to 1."
            ),
        }), 400

    if (
        per_page < 1
        or per_page > 100
    ):

        return jsonify({
            "success": False,
            "message": (
                "per_page must be "
                "between 1 and 100."
            ),
        }), 400

    # ---------------------------------------------------------
    # Build query
    # ---------------------------------------------------------

    query = AuditLog.query

    action = request.args.get(
        "action",
        type=str,
    )

    user_id = request.args.get(
        "user_id",
        type=int,
    )

    if action:

        query = query.filter(
            AuditLog.action == action
        )

    if user_id is not None:

        query = query.filter(
            AuditLog.user_id == user_id
        )

    # ---------------------------------------------------------
    # Newest records first
    # ---------------------------------------------------------

    query = query.order_by(
        AuditLog.created_at.desc()
    )

    # ---------------------------------------------------------
    # Pagination
    # ---------------------------------------------------------

    pagination = query.paginate(
        page=page,
        per_page=per_page,
        error_out=False,
    )

    logs = []

    for log in pagination.items:

        details = None

        if log.details:

            try:

                details = json.loads(
                    log.details
                )

            except (
                TypeError,
                ValueError,
            ):

                details = {
                    "message": log.details
                }

        logs.append({
            "id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "resource": log.resource,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "details": details,
            "created_at": (
                log.created_at.isoformat()
                if log.created_at
                else None
            ),
        })

    return jsonify({
        "success": True,
        "audit_logs": logs,
        "pagination": {
            "page": pagination.page,
            "per_page": pagination.per_page,
            "total": pagination.total,
            "pages": pagination.pages,
            "has_next": pagination.has_next,
            "has_previous": pagination.has_prev,
        },
    }), 200


# ============================================================
# SYSTEM STATUS
# ============================================================

@admin_bp.get("/system-status")
@jwt_required()
@roles_required("ADMIN")
def system_status():
    """
    Return a consolidated system-status view.

    Administrator access only.
    """

    # ---------------------------------------------------------
    # Database status
    # ---------------------------------------------------------

    database_status = "healthy"

    try:

        db.session.execute(
            db.text("SELECT 1")
        )

    except Exception:

        database_status = "unhealthy"

    # ---------------------------------------------------------
    # ML model status
    # ---------------------------------------------------------

    try:

        ml_model_status = (
            "available"
            if model_manager.artifacts_exist()
            else "unavailable"
        )

    except Exception:

        ml_model_status = "unavailable"

    # ---------------------------------------------------------
    # Monitoring status
    # ---------------------------------------------------------

    try:

        monitoring = (
            network_monitor.get_status()
        )

        monitoring_status = (
            "running"
            if monitoring.get("running")
            else "stopped"
        )

    except Exception:

        monitoring = {}

        monitoring_status = (
            "unavailable"
        )

    # ---------------------------------------------------------
    # Alert statistics
    # ---------------------------------------------------------

    try:

        alert_statistics = (
            alert_service.get_statistics()
        )

    except Exception:

        alert_statistics = {
            "total": 0,
            "open": 0,
            "acknowledged": 0,
            "resolved": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        }

    # ---------------------------------------------------------
    # Overall application status
    # ---------------------------------------------------------

    application_status = (
        "healthy"
        if (
            database_status == "healthy"
            and ml_model_status == "available"
            and monitoring_status
            != "unavailable"
        )
        else "degraded"
    )

    return jsonify({
        "success": True,
        "system": {
            "application": (
                application_status
            ),
            "database": (
                database_status
            ),
            "ml_model": (
                ml_model_status
            ),
            "monitoring": (
                monitoring_status
            ),
            "alerts": (
                alert_statistics
            ),
        },
    }), 200
@admin_bp.get("/config")
@jwt_required()
@roles_required("ADMIN")
def get_admin_config():
    """Return safe, non-secret application configuration."""
    from config import Config

    return jsonify({
        "success": True,
        "config": {
            "database": {
                "type": (
                    "sqlite"
                    if Config.SQLALCHEMY_DATABASE_URI.startswith("sqlite:///")
                    else "external"
                )
            },
            "jwt": {
                "access_token_minutes": int(
                    Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds() / 60
                ),
                "refresh_token_days": int(
                    Config.JWT_REFRESH_TOKEN_EXPIRES.total_seconds() / 86400
                ),
                "token_location": Config.JWT_TOKEN_LOCATION,
                "header_name": Config.JWT_HEADER_NAME,
                "header_type": Config.JWT_HEADER_TYPE,
            },
            "cors": {
                "origins": Config.CORS_ORIGINS,
            },
            "authentication": {
                "password_min_length": Config.PASSWORD_MIN_LENGTH,
                "login_rate_limit": Config.LOGIN_RATE_LIMIT,
                "rate_limiting_enabled": Config.ENABLE_RATE_LIMITING,
            },
            "security": {
                "secret_keys_exposed": False,
            },
        },
    }), 200