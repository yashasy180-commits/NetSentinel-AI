from flask import (
    Blueprint,
    jsonify,
)

from flask_jwt_extended import jwt_required

from security.authentication import (
    active_user_required,
)


user_bp = Blueprint(
    "users",
    __name__,
    url_prefix="/api/users",
)


@user_bp.get("/me")
@jwt_required()
def get_profile():

    user, error = (
        active_user_required()
    )

    if error:
        return error

    return jsonify({
        "success": True,
        "user": user.to_dict(),
    }), 200