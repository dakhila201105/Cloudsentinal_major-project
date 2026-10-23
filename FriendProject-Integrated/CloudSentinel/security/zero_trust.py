"""
Zero Trust Layer
-----------------
"Never trust, always verify." Evaluates device, location, and session
characteristics on every request rather than assuming trust after login.
"""

import hashlib


def compute_device_fingerprint(user_agent: str, accept_lang: str, ip: str) -> str:
    """
    Builds a lightweight, deterministic device fingerprint out of
    request characteristics. In a production system this would also
    include canvas/WebGL fingerprinting, TLS fingerprinting, etc.
    """
    raw = f"{user_agent}|{accept_lang}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def is_known_device(user, fingerprint, Device) -> bool:
    return Device.query.filter_by(user_id=user.id, fingerprint=fingerprint).first() is not None


def simulate_geo_lookup(ip: str) -> str:
    """
    Simulates a geo-IP lookup. Private/loopback ranges are treated as
    'Local Network'; everything else is bucketed deterministically so
    demo behaviour stays repeatable without calling an external API.
    """
    if ip in ("127.0.0.1", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
        return "Local Network"
    buckets = ["Hyderabad, IN", "Mumbai, IN", "Singapore", "Frankfurt, DE", "Ashburn, US"]
    idx = sum(ord(c) for c in ip) % len(buckets)
    return buckets[idx]


def is_known_location(user, location, LoginLog) -> bool:
    previous = (
        LoginLog.query.filter_by(user_id=user.id, success=True)
        .filter(LoginLog.location == location)
        .first()
    )
    return previous is not None
