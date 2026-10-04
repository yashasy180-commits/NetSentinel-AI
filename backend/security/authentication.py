from functools import wraps

from flask import jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request

from extensions.database import db
from models.user import User


def db_user_by_id(user_id):
    """Return a user by database ID."""
    if not user_id:
        return None

    try:
        return db.session.get(User, int(user_id))
    except (TypeError, ValueError):
        return None


def get_current_user():
    """Return the currently authenticated user."""
    user_id = get_jwt_identity()
    return db_user_by_id(user_id)


def _get_active_user():
    """
    Verify the JWT and return the active user.

    Returns:
        (user, None) when authentication succeeds.
        (None, response) when authentication fails.
    """
    verify_jwt_in_request()

    user = get_current_user()

    if user is None:
        return None, (
            jsonify({
                "success": False,
                "message": "User account not found."
            }),
            401,
        )

    if not user.is_active:
        return None, (
            jsonify({
                "success": False,
                "message": "User account is inactive."
            }),
            403,
        )

    return user, None


def active_user_required(view_function=None):
    """
    Require an authenticated and active user.

    Supports both styles:

        @active_user_required
        def route():
            ...

    and:

        user, error = active_user_required()
    """

    # Function-call style
    if view_function is None:
        return _get_active_user()

    # Decorator style
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):
        user, error = _get_active_user()

        if error:
            return error

        return view_function(*args, **kwargs)

    return wrapped_view


def get_authenticated_user():
    """Return the authenticated active user or None."""
    user, error = _get_active_user()

    if error:
        return None

    return user