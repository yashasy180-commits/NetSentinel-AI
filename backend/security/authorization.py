from functools import wraps

from flask import jsonify

from flask_jwt_extended import (
    get_jwt,
    get_jwt_identity,
)

from extensions.database import db
from models.user import User


def roles_required(*allowed_roles: str):
    """
    Require an authenticated active user with
    one of the specified roles.
    """

    normalized_roles = {
        role.upper()
        for role in allowed_roles
    }

    def decorator(fn):

        @wraps(fn)
        def wrapper(*args, **kwargs):

            claims = get_jwt()

            role = str(
                claims.get("role", "")
            ).upper()

            if role not in normalized_roles:
                return jsonify({
                    "success": False,
                    "message": (
                        "You do not have permission "
                        "to perform this action."
                    ),
                }), 403

            try:
                user_id = int(
                    get_jwt_identity()
                )
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
                        "This account is inactive "
                        "or unavailable."
                    ),
                }), 403

            return fn(
                *args,
                **kwargs,
            )

        return wrapper

    return decorator