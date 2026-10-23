from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from extensions import db


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="user")  # admin | user | analyst
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    devices = db.relationship("Device", backref="user", lazy=True)
    login_logs = db.relationship("LoginLog", backref="user", lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    fingerprint = db.Column(db.String(128), nullable=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    trusted = db.Column(db.Boolean, default=True)


class LoginLog(db.Model):
    __tablename__ = "login_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    username_attempted = db.Column(db.String(80))
    ip_address = db.Column(db.String(64))
    device_fingerprint = db.Column(db.String(128))
    user_agent = db.Column(db.String(255))
    location = db.Column(db.String(80))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    success = db.Column(db.Boolean, default=False)
    risk_score = db.Column(db.Float, default=0)
    risk_level = db.Column(db.String(10))       # LOW / MEDIUM / HIGH
    decision = db.Column(db.String(30))          # ALLOWED / LIMITED / HONEYPOT / BLOCKED


class ThreatLog(db.Model):
    __tablename__ = "threat_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    source_ip = db.Column(db.String(64))
    description = db.Column(db.String(255))
    severity = db.Column(db.String(10))


class HoneypotLog(db.Model):
    __tablename__ = "honeypot_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(64))
    username_attempted = db.Column(db.String(80))
    action = db.Column(db.String(255))


class ReplicaStatus(db.Model):
    __tablename__ = "replica_status"

    id = db.Column(db.Integer, primary_key=True)
    primary_frozen = db.Column(db.Boolean, default=False)
    replica_active = db.Column(db.Boolean, default=False)
    last_triggered = db.Column(db.DateTime)
    reason = db.Column(db.String(255))


class SystemState(db.Model):
    """Singleton-ish row storing global lockdown state."""
    __tablename__ = "system_state"

    id = db.Column(db.Integer, primary_key=True)
    lockdown = db.Column(db.Boolean, default=False)
    lockdown_reason = db.Column(db.String(255))
    lockdown_since = db.Column(db.DateTime)


class PendingApproval(db.Model):
    """
    Tracks a new/unknown-device login that requires BOTH the account
    owner's approval and the administrator's approval before access is
    granted (Dual Approval Zero-Trust workflow).
    """
    __tablename__ = "pending_approvals"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Captured context of the suspicious/unknown login attempt
    device_fingerprint = db.Column(db.String(128))
    ip_address = db.Column(db.String(64))
    location = db.Column(db.String(80))
    user_agent = db.Column(db.String(255))
    risk_score = db.Column(db.Float)
    risk_level = db.Column(db.String(10))
    ai_anomaly = db.Column(db.Float)
    reasons = db.Column(db.String(500))

    # Account-owner approval OTP
    user_otp = db.Column(db.String(6))
    user_otp_expires = db.Column(db.DateTime)
    user_approved = db.Column(db.Boolean, default=False)
    user_attempts = db.Column(db.Integer, default=0)

    # Administrator approval OTP
    admin_otp = db.Column(db.String(6))
    admin_otp_expires = db.Column(db.DateTime)
    admin_approved = db.Column(db.Boolean, default=False)
    admin_attempts = db.Column(db.Integer, default=0)

    # PENDING_USER -> PENDING_ADMIN -> APPROVED | DENIED | EXPIRED
    status = db.Column(db.String(20), default="PENDING_USER")

    user = db.relationship("User")


class AuditLog(db.Model):
    """
    Immutable authentication audit trail. Rows are only ever inserted,
    never updated or deleted, by design (no update/delete route exists
    for this table anywhere in the app).
    """
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    username = db.Column(db.String(80))
    device_id = db.Column(db.String(128))
    browser = db.Column(db.String(255))
    ip_address = db.Column(db.String(64))
    country = db.Column(db.String(80))
    auth_status = db.Column(db.String(40))     # e.g. ALLOWED, AWAITING_ADMIN, DENIED, APPROVED
    risk_score = db.Column(db.Float)
    admin_decision = db.Column(db.String(20))  # APPROVED / DENIED / N/A


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), unique=True, nullable=False)
    blocked_since = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_until = db.Column(db.DateTime)
    reason = db.Column(db.String(255))


class AccessRequest(db.Model):
    """
    Tracks access requests that require administrator approval after OTP verification.
    This is the new workflow where ALL logins require admin approval.
    """
    __tablename__ = "access_requests"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Device and context information
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    ip_address = db.Column(db.String(64))
    mac_address = db.Column(db.String(64))  # Best effort MAC address
    device_fingerprint = db.Column(db.String(128))
    browser = db.Column(db.String(255))
    operating_system = db.Column(db.String(100))
    location = db.Column(db.String(80))
    
    # Request status
    status = db.Column(db.String(20), default="PENDING")  # PENDING, APPROVED, DENIED
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Approval tracking
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)
    approval_code_id = db.Column(db.Integer, db.ForeignKey("approval_codes.id"), nullable=True)
    
    user = db.relationship("User", foreign_keys=[user_id])
    admin = db.relationship("User", foreign_keys=[approved_by])


class ApprovalCode(db.Model):
    """
    Stores one-time approval codes sent to administrators for access request approval.
    Codes are hashed and expire after a configurable duration.
    """
    __tablename__ = "approval_codes"

    id = db.Column(db.Integer, primary_key=True)
    code_hash = db.Column(db.String(255), nullable=False)  # Hashed approval code
    access_request_id = db.Column(db.Integer, db.ForeignKey("access_requests.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    
    access_request = db.relationship("AccessRequest", foreign_keys=[access_request_id])


class ActiveSession(db.Model):
    """
    Tracks active user sessions for monitoring and preventing multiple device access.
    """
    __tablename__ = "active_sessions"

    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(128), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    
    # Device information
    mac_address = db.Column(db.String(64))
    device_fingerprint = db.Column(db.String(128))
    ip_address = db.Column(db.String(64))
    browser = db.Column(db.String(255))
    operating_system = db.Column(db.String(100))
    
    # Session tracking
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default="ACTIVE")  # ACTIVE, TERMINATED
    
    # Approval tracking
    approved_by = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    approval_time = db.Column(db.DateTime, nullable=True)
    
    user = db.relationship("User", foreign_keys=[user_id])
    admin = db.relationship("User", foreign_keys=[approved_by])
