from models.user import User
from models.audit_log import AuditLog
from models.token_blocklist import TokenBlocklist
from models.alert import Alert


def register_models():
    """
    Import all SQLAlchemy models so Flask-SQLAlchemy
    can discover them before db.create_all().
    """
    return {
        "User": User,
        "AuditLog": AuditLog,
        "TokenBlocklist": TokenBlocklist,
        "Alert": Alert,
    }