import pytest

from app import create_app
from extensions.database import db


@pytest.fixture()
def client(tmp_path):

    app = create_app({
        "TESTING": True,

        "SQLALCHEMY_DATABASE_URI": (
            f"sqlite:///"
            f"{tmp_path / 'test.db'}"
        ),

        "JWT_SECRET_KEY":
            "test-jwt-secret",

        "SECRET_KEY":
            "test-secret",

        "ENABLE_RATE_LIMITING":
            False,
    })

    with app.app_context():

        db.drop_all()

        db.create_all()

    with app.test_client() as test_client:

        yield test_client

    with app.app_context():

        db.session.remove()

        db.drop_all()


def register_user(client):

    return client.post(
        "/api/auth/register",
        json={
            "username":
                "analyst1",

            "email":
                "analyst1@example.com",

            "password":
                "StrongPass1!",
        },
    )


def login_user(client):

    return client.post(
        "/api/auth/login",
        json={
            "identifier":
                "analyst1",

            "password":
                "StrongPass1!",
        },
    )


# ============================================================
# REGISTRATION
# ============================================================

def test_register_user(client):

    response = (
        register_user(client)
    )

    assert (
        response.status_code
        == 201
    )

    assert (
        response.json["success"]
        is True
    )

    assert (
        response.json["user"]["role"]
        == "ANALYST"
    )


# ============================================================
# LOGIN
# ============================================================

def test_login_returns_tokens(client):

    register_user(client)

    response = (
        login_user(client)
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        "access_token"
        in response.json
    )

    assert (
        "refresh_token"
        in response.json
    )


# ============================================================
# INVALID LOGIN
# ============================================================

def test_invalid_login_is_rejected(
    client,
):

    register_user(client)

    response = client.post(
        "/api/auth/login",
        json={
            "identifier":
                "analyst1",

            "password":
                "WrongPassword1!",
        },
    )

    assert (
        response.status_code
        == 401
    )


# ============================================================
# PROTECTED ENDPOINT
# ============================================================

def test_protected_profile_requires_jwt(
    client,
):

    response = client.get(
        "/api/auth/me"
    )

    assert (
        response.status_code
        == 401
    )


# ============================================================
# AUTHENTICATED PROFILE
# ============================================================

def test_authenticated_profile(
    client,
):

    register_user(client)

    login = login_user(
        client
    )

    token = (
        login.json[
            "access_token"
        ]
    )

    response = client.get(
        "/api/auth/me",
        headers={
            "Authorization":
                f"Bearer {token}"
        },
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        response.json[
            "user"
        ]["username"]
        == "analyst1"
    )


# ============================================================
# LOGOUT / TOKEN REVOCATION
# ============================================================

def test_logout_revokes_session_tokens(
    client,
):

    register_user(client)

    login = login_user(
        client
    )

    access_token = (
        login.json[
            "access_token"
        ]
    )

    refresh_token = (
        login.json[
            "refresh_token"
        ]
    )

    access_headers = {
        "Authorization":
            f"Bearer {access_token}"
    }

    refresh_headers = {
        "Authorization":
            f"Bearer {refresh_token}"
    }

    logout = client.post(
        "/api/auth/logout",
        headers=access_headers,
    )

    assert (
        logout.status_code
        == 200
    )

    profile = client.get(
        "/api/auth/me",
        headers=access_headers,
    )

    assert (
        profile.status_code
        == 401
    )

    refresh = client.post(
        "/api/auth/refresh",
        headers=refresh_headers,
    )

    assert (
        refresh.status_code
        == 401
    )