from flask import (
    Blueprint,
    jsonify,
    request,
)

from flask_jwt_extended import (
    create_access_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)

from extensions.database import db
from models.token_blocklist import TokenBlocklist
from models.user import User
from security.audit import write_audit_log
from security.authentication import (
    active_user_required,
)
from services.auth_service import AuthService


auth_bp = Blueprint(
    "auth",
    __name__,
    url_prefix="/api/auth",
)


def _json_body() -> dict:
    payload = request.get_json(
        silent=True
    )

    if isinstance(payload, dict):
        return payload

    return {}


# ============================================================
# REGISTER
# ============================================================

@auth_bp.post("/register")
def register():

    payload = _json_body()

    username = payload.get("username")
    email = payload.get("email")
    password = payload.get("password")

    if not all(
        isinstance(value, str)
        for value in (
            username,
            email,
            password,
        )
    ):
        return jsonify({
            "success": False,
            "message": (
                "username, email and password "
                "are required."
            ),
        }), 400

    try:

        user, errors = AuthService.register(
            username,
            email,
            password,
        )

    except Exception:

        return jsonify({
            "success": False,
            "message": (
                "Unable to create the account."
            ),
        }), 500

    if errors:

        return jsonify({
            "success": False,
            "message": (
                "Registration validation failed."
            ),
            "errors": errors,
        }), 400

    return jsonify({
        "success": True,
        "message": (
            "Account created successfully."
        ),
        "user": user.to_dict(),
    }), 201


# ============================================================
# LOGIN
# ============================================================

@auth_bp.post("/login")
def login():

    payload = _json_body()

    identifier = payload.get(
        "identifier"
    )

    password = payload.get(
        "password"
    )

    if (
        not isinstance(identifier, str)
        or not isinstance(password, str)
    ):
        return jsonify({
            "success": False,
            "message": (
                "identifier and password "
                "are required."
            ),
        }), 400

    try:

        result, error = (
            AuthService.authenticate(
                identifier,
                password,
            )
        )

    except Exception:

        return jsonify({
            "success": False,
            "message": (
                "Authentication service "
                "is temporarily unavailable."
            ),
        }), 500

    if error:

        return jsonify({
            "success": False,
            "message": error,
        }), 401

    return jsonify({
        "success": True,
        "message": "Login successful.",
        **result,
    }), 200


# ============================================================
# REFRESH TOKEN
# ============================================================

@auth_bp.post("/refresh")
@jwt_required(refresh=True)
def refresh():

    identity = get_jwt_identity()

    try:
        user_id = int(identity)
    except (
        TypeError,
        ValueError,
    ):
        return jsonify({
            "success": False,
            "message": (
                "Invalid authentication identity."
            ),
        }), 401

    user = db.session.get(
        User,
        user_id,
    )

    if user is None or not user.is_active:

        return jsonify({
            "success": False,
            "message": (
                "User account is unavailable."
            ),
        }), 401

    claims = {
        "role": user.role,
        "username": user.username,
        "session_id": get_jwt().get(
            "session_id"
        ),
    }

    access_token = create_access_token(
        identity=str(user.id),
        additional_claims=claims,
    )

    return jsonify({
        "success": True,
        "access_token": access_token,
    }), 200


# ============================================================
# LOGOUT
# ============================================================

@auth_bp.post("/logout")
@jwt_required()
def logout():

    claims = get_jwt()

    identity = get_jwt_identity()

    jti = claims["jti"]

    token_type = claims.get(
        "type",
        "access",
    )

    session_id = claims.get(
        "session_id"
    )

    if not session_id:

        return jsonify({
            "success": False,
            "message": (
                "Invalid authentication session."
            ),
        }), 401

    existing = (
        TokenBlocklist.query
        .filter_by(
            session_id=session_id
        )
        .first()
    )

    if existing is None:

        db.session.add(
            TokenBlocklist(
                jti=jti,
                session_id=session_id,
                token_type=token_type,
                user_id=int(identity),
            )
        )

    try:

        write_audit_log(
            action="USER_LOGOUT",
            user_id=int(identity),
            resource="auth",
        )

        db.session.commit()

    except Exception:

        db.session.rollback()

        return jsonify({
            "success": False,
            "message": (
                "Unable to complete logout."
            ),
        }), 500

    return jsonify({
        "success": True,
        "message": "Logout successful.",
    }), 200


# ============================================================
# CURRENT USER
# ============================================================

@auth_bp.get("/me")
@jwt_required()
def me():

    user, error = (
        active_user_required()
    )

    if error:
        return error

    return jsonify({
        "success": True,
        "user": user.to_dict(),
    }), 200