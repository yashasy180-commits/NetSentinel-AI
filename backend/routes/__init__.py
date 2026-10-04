from routes.auth_routes import auth_bp
from routes.user_routes import user_bp
from routes.admin_routes import admin_bp
from routes.traffic_routes import traffic_bp
from routes.monitoring_routes import monitoring_bp
from routes.alert_routes import alert_bp
from routes.analytics_routes import analytics_bp
from routes.report_routes import report_bp

__all__ = [
    "auth_bp",
    "user_bp",
    "admin_bp",
    "traffic_bp",
    "monitoring_bp",
    "alert_bp",
    "analytics_bp",
    "report_bp",
]