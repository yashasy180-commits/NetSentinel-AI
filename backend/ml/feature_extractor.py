FEATURES = [
    "packet_count",
    "byte_count",
    "duration",
    "packet_rate",
    "byte_rate"
]

def extract_features(flow):
    duration = max(float(flow.get("duration", 0)), 0.001)
    packets = float(flow.get("packet_count", 0))
    bytes_ = float(flow.get("byte_count", 0))
    return {
        "packet_count": packets,
        "byte_count": bytes_,
        "duration": duration,
        "packet_rate": packets / duration,
        "byte_rate": bytes_ / duration
    }
