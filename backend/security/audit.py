import json

from flask import has_request_context, request

from extensions.database import db
from models.audit_log import AuditLog


def write_audit_log(
    action,
    resource=None,
    user_id=None,
    details=None,
    ip_address=None,
    user_agent=None,
):
    """
    Create an audit log entry.

    This function supports both:
    1. Normal HTTP requests
    2. Background/CLI operations such as create_admin.py
    """

    # ---------------------------------------------------------
    # Request information
    # ---------------------------------------------------------
    if has_request_context():

        if ip_address is None:
            forwarded_for = request.headers.get("X-Forwarded-For")

            if forwarded_for:
                ip_address = forwarded_for.split(",")[0].strip()
            else:
                ip_address = request.remote_addr

        if user_agent is None:
            user_agent = request.headers.get("User-Agent")

    else:
        # CLI/background operation
        if ip_address is None:
            ip_address = "CLI"

        if user_agent is None:
            user_agent = "NetSentinel-AI-CLI"

    # ---------------------------------------------------------
    # Safely serialize details
    # ---------------------------------------------------------
    serialized_details = None

    if details is not None:
        try:
            serialized_details = json.dumps(
                details,
                default=str,
            )
        except (TypeError, ValueError):
            serialized_details = json.dumps({
                "message": str(details)
            })

    # ---------------------------------------------------------
    # Create audit record
    # ---------------------------------------------------------
    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        resource=resource,
        ip_address=ip_address,
        user_agent=user_agent,
        details=serialized_details,
    )

    db.session.add(audit_entry)

    return audit_entry