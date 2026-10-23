"""
Decoy Honeypot + Hidden Data Replication + Emergency Lockdown responses.
These are the automated actions triggered for HIGH risk logins.
"""

from datetime import datetime, timedelta


def trigger_high_risk_response(db, ReplicaStatus, ThreatLog, ip, reason):
    """Freeze primary storage (simulated) and activate the hidden replica."""
    status = ReplicaStatus.query.first()
    if status is None:
        status = ReplicaStatus()
        db.session.add(status)

    status.primary_frozen = True
    status.replica_active = True
    status.last_triggered = datetime.utcnow()
    status.reason = reason

    threat = ThreatLog(
        source_ip=ip,
        description=reason,
        severity="HIGH",
    )
    db.session.add(threat)
    db.session.commit()
    return status


def check_auto_lockdown(db, SystemState, ThreatLog, cfg):
    """
    If HIGH severity threats exceed the threshold within the configured
    window, automatically engage emergency lockdown.
    """
    window_start = datetime.utcnow() - timedelta(minutes=cfg.LOCKDOWN_WINDOW_MINUTES)
    recent_high = ThreatLog.query.filter(
        ThreatLog.severity == "HIGH", ThreatLog.timestamp >= window_start
    ).count()

    state = SystemState.query.first()
    if state is None:
        state = SystemState(lockdown=False)
        db.session.add(state)
        db.session.commit()

    if recent_high >= cfg.LOCKDOWN_HIGH_RISK_THRESHOLD and not state.lockdown:
        state.lockdown = True
        state.lockdown_reason = f"{recent_high} high-risk events within {cfg.LOCKDOWN_WINDOW_MINUTES} minutes"
        state.lockdown_since = datetime.utcnow()
        db.session.commit()

    return state
