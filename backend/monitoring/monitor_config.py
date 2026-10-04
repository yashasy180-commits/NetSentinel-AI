"""
NetSentinel AI
Module 5 - Real-Time Monitoring Configuration
"""

# Maximum packets processed during one monitoring window.
MAX_PACKETS_PER_WINDOW = 5000

# Default monitoring window in seconds.
WINDOW_SECONDS = 10

# Maximum number of flows processed per window.
MAX_FLOWS_PER_WINDOW = 1000

# Socket.IO event names.
TRAFFIC_EVENT = "traffic_update"
THREAT_EVENT = "threat_detected"
MONITOR_STATUS_EVENT = "monitor_status"

# Safe default:
# Monitoring only observes traffic.
# It does not block, terminate, or modify connections.
AUTO_MITIGATION_ENABLED = False