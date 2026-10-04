from app import app
from extensions.database import db
from models.user import User
from security.audit import write_audit_log
from security.validators import (
    validate_email,
    validate_password,
    validate_username,
)


def main():
    print("NetSentinel AI - Admin Account Setup")
    print("------------------------------------")

    username = input("Admin username: ").strip()
    email = input("Admin email: ").strip().lower()
    password = input("Admin password: ")
    confirm_password = input("Confirm password: ")

    if not username or not email or not password:
        print("Error: username, email and password are required.")
        return

    if password != confirm_password:
        print("Error: passwords do not match.")
        return

    # Flask current_app is required by the validators,
    # so validation must happen inside the application context.
    with app.app_context():

        username_error = validate_username(username)
        if username_error:
            print(f"Error: {username_error}")
            return

        email_error = validate_email(email)
        if email_error:
            print(f"Error: {email_error}")
            return

        password_error = validate_password(password)
        if password_error:
            print(f"Error: {password_error}")
            return

        existing_username = User.query.filter_by(
            username=username
        ).first()

        if existing_username:
            print("Error: username already exists.")
            return

        existing_email = User.query.filter_by(
            email=email
        ).first()

        if existing_email:
            print("Error: email already exists.")
            return

        admin = User(
            username=username,
            email=email,
            role="ADMIN",
            is_active=True,
        )

        admin.set_password(password)

        db.session.add(admin)
        db.session.flush()

        write_audit_log(
            action="ADMIN_CREATED",
            resource=f"user:{admin.id}",
            user_id=admin.id,
            details={
                "username": admin.username,
                "role": admin.role,
            },
        )

        db.session.commit()

        print()
        print("====================================")
        print("Admin account created successfully.")
        print("====================================")
        print(f"Username: {admin.username}")
        print(f"Email: {admin.email}")
        print("Role: ADMIN")


if __name__ == "__main__":
    main()