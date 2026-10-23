"""
Dynamic Risk Assessment + Adaptive Firewall Decision Engine
------------------------------------------------------------
Combines rule-based scoring with the AI anomaly score to produce a
final 0-100 risk score, classifies it, and decides the firewall action.
"""

from datetime import datetime
from security.ai_engine import anomaly_score


def _setting(cfg, name):
    """Read a setting from either Flask's config mapping or a config object."""
    return cfg.get(name) if hasattr(cfg, "get") else getattr(cfg, name)


def compute_risk(cfg, hour, known_device, known_location, failed_attempts, requests_per_min):
    score = 0.0
    reasons = []

    if not known_device:
        score += _setting(cfg, "WEIGHT_NEW_DEVICE")
        reasons.append("Unrecognized device")

    if not known_location:
        score += _setting(cfg, "WEIGHT_NEW_LOCATION")
        reasons.append("Unusual login location")

    if hour < 6 or hour > 23:
        score += _setting(cfg, "WEIGHT_UNUSUAL_HOUR")
        reasons.append("Login during unusual hours")

    failed_component = min(failed_attempts * _setting(cfg, "WEIGHT_FAILED_ATTEMPTS"), _setting(cfg, "WEIGHT_FAILED_ATTEMPTS_CAP"))
    if failed_component:
        score += failed_component
        reasons.append(f"{failed_attempts} recent failed attempt(s)")

    if requests_per_min > 10:
        score += _setting(cfg, "WEIGHT_RAPID_REQUESTS")
        reasons.append("Abnormally rapid request rate")

    ai_anom = anomaly_score(hour, int(known_device), int(known_location), failed_attempts, requests_per_min)
    ai_component = ai_anom * _setting(cfg, "AI_WEIGHT")
    score += ai_component
    if ai_anom > 0.6:
        reasons.append("AI behavior engine flagged deviation from normal pattern")

    score = round(min(score, 100), 1)

    if score <= _setting(cfg, "RISK_LOW_MAX"):
        level = "LOW"
    elif score <= _setting(cfg, "RISK_MEDIUM_MAX"):
        level = "MEDIUM"
    else:
        level = "HIGH"

    return score, level, reasons, round(ai_anom, 3)


def decide_action(level):
    """Adaptive Firewall Decision Engine."""
    if level == "LOW":
        return "ALLOWED"
    if level == "MEDIUM":
        return "LIMITED"
    return "HONEYPOT"
