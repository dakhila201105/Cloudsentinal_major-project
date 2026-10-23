"""
Dual Approval Workflow Helpers
--------------------------------
Small utilities shared by the login / device-approval / admin-approval
routes in app.py: OTP generation, immutable audit logging, and the
escalation path for repeated denied attempts (IP block -> honeypot ->
replica activation -> emergency lockdown).
"""

import random
import string
import hashlib
from datetime import datetime, timedelta


def generate_otp():
    return "".join(random.choices(string.digits, k=6))


def generate_approval_code(length=8):
    """Generate an alphanumeric approval code."""
    chars = string.ascii_uppercase + string.digits
    return "".join(random.choices(chars, k=length))


def hash_approval_code(code):
    """Hash an approval code for secure storage."""
    return hashlib.sha256(code.encode()).hexdigest()


def verify_approval_code(code, code_hash):
    """Verify an approval code against its hash."""
    return hashlib.sha256(code.encode()).hexdigest() == code_hash


def extract_browser_info(user_agent):
    """Extract browser and OS information from user agent string."""
    browser = "Unknown"
    os = "Unknown"
    
    ua_lower = user_agent.lower()
    
    # Browser detection
    if "chrome" in ua_lower and "edge" not in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        browser = "Safari"
    elif "edge" in ua_lower:
        browser = "Edge"
    elif "opera" in ua_lower:
        browser = "Opera"
    
    # OS detection
    if "windows" in ua_lower:
        os = "Windows"
    elif "mac" in ua_lower or "os x" in ua_lower:
        os = "macOS"
    elif "linux" in ua_lower:
        os = "Linux"
    elif "android" in ua_lower:
        os = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os = "iOS"
    
    return browser, os


def write_audit_log(db, AuditLog, *, username, device_id, browser, ip_address,
                     country, auth_status, risk_score, admin_decision="N/A"):
    """Append-only audit trail entry. Never updated or deleted anywhere in the app."""
    entry = AuditLog(
        username=username,
        device_id=device_id,
        browser=browser,
        ip_address=ip_address,
        country=country,
        auth_status=auth_status,
        risk_score=risk_score,
        admin_decision=admin_decision,
    )
    db.session.add(entry)
    db.session.commit()
    return entry


def is_ip_blocked(BlockedIP, ip):
    row = BlockedIP.query.filter_by(ip_address=ip).first()
    if row is None:
        return False
    if row.blocked_until and row.blocked_until < datetime.utcnow():
        return False  # block has expired
    return True


def record_denial_and_escalate(db, models, cfg, ip, username, reason):
    """
    Called whenever a user or admin approval is denied/expired/wrong.
    Escalates: raises a threat log entry every time, and if repeated
    denials pile up for this IP within the lockdown window, blocks the
    IP, activates the honeypot posture, freezes primary storage,
    activates the hidden replica, and may trigger emergency lockdown.
    """
    from security.honeypot import trigger_high_risk_response, check_auto_lockdown

    ThreatLog = models["ThreatLog"]
    BlockedIP = models["BlockedIP"]
    ReplicaStatus = models["ReplicaStatus"]
    SystemState = models["SystemState"]

    threat_reason = f"Denied dual-approval login for '{username}' from {ip}: {reason}"
    trigger_high_risk_response(db, ReplicaStatus, ThreatLog, ip, threat_reason)

    window_start = datetime.utcnow() - timedelta(minutes=cfg.LOCKDOWN_WINDOW_MINUTES)
    recent_denials = ThreatLog.query.filter(
        ThreatLog.source_ip == ip, ThreatLog.timestamp >= window_start
    ).count()

    if recent_denials >= cfg.LOCKDOWN_HIGH_RISK_THRESHOLD:
        existing = BlockedIP.query.filter_by(ip_address=ip).first()
        if existing is None:
            db.session.add(BlockedIP(
                ip_address=ip,
                blocked_until=datetime.utcnow() + timedelta(minutes=cfg.LOCKDOWN_WINDOW_MINUTES * 3),
                reason=f"{recent_denials} denied approval attempts within {cfg.LOCKDOWN_WINDOW_MINUTES} minutes",
            ))
            db.session.commit()

    check_auto_lockdown(db, SystemState, ThreatLog, cfg)
