import os
import random
import string
import hashlib
import json
from datetime import datetime, timedelta

from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_user, login_required, logout_user, current_user

from config import Config, BASE_DIR
from extensions import db, login_manager
from models import (
    User, Device, LoginLog, ThreatLog, HoneypotLog, ReplicaStatus,
    SystemState, PendingApproval, AuditLog, BlockedIP,
    AccessRequest, ApprovalCode, ActiveSession,
)
from security.zero_trust import compute_device_fingerprint, is_known_device, simulate_geo_lookup, is_known_location
from security.risk_engine import compute_risk
from security.honeypot import trigger_high_risk_response, check_auto_lockdown
from security.mailer import send_login_otp, send_new_device_approval, send_admin_alert, send_denial_notice, send_access_request_alert
from security.dual_approval import generate_otp, write_audit_log, is_ip_blocked, record_denial_and_escalate, generate_approval_code, hash_approval_code, verify_approval_code, extract_browser_info
from integration import bp as integration_bp
from integration_models import IntegrationAccessRequest

MODELS = {
    "ThreatLog": ThreatLog, "BlockedIP": BlockedIP,
    "ReplicaStatus": ReplicaStatus, "SystemState": SystemState,
}


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        os.makedirs(os.path.join(BASE_DIR, "instance"), exist_ok=True)
        db.create_all()
        from sqlalchemy import inspect, text
        if "ended_at" not in {column["name"] for column in inspect(db.engine).get_columns("security_sessions")}:
            db.session.execute(text("ALTER TABLE security_sessions ADD COLUMN ended_at DATETIME"))
            db.session.commit()
        if "request_type" not in {column["name"] for column in inspect(db.engine).get_columns("integration_access_requests")}:
            db.session.execute(text("ALTER TABLE integration_access_requests ADD COLUMN request_type VARCHAR(40) NOT NULL DEFAULT 'RISK_REVIEW'"))
            db.session.commit()
        if SystemState.query.first() is None:
            db.session.add(SystemState(lockdown=False))
        if ReplicaStatus.query.first() is None:
            db.session.add(ReplicaStatus(primary_frozen=False, replica_active=False))
        if User.query.filter_by(username="admin").first() is None:
            admin = User(username="admin", email=Config.ADMIN_NOTIFY_EMAIL or "admin@cloudsentinel.local", role="admin")
            admin.set_password("Admin@123")
            db.session.add(admin)
        db.session.commit()

    app.register_blueprint(integration_bp)
    register_routes(app)
    return app


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# --------------------------------------------------------------------------
# In-memory rate-limit helpers (per-process demo state)
# --------------------------------------------------------------------------
FAILED_ATTEMPTS = {}
REQUEST_TIMES = {}


def record_request(ip):
    now = datetime.utcnow()
    times = REQUEST_TIMES.setdefault(ip, [])
    times.append(now)
    cutoff = now - timedelta(minutes=1)
    REQUEST_TIMES[ip] = [t for t in times if t > cutoff]
    return len(REQUEST_TIMES[ip])


def recent_failed_attempts(username):
    now = datetime.utcnow()
    cutoff = now - timedelta(minutes=15)
    times = [t for t in FAILED_ATTEMPTS.get(username, []) if t > cutoff]
    FAILED_ATTEMPTS[username] = times
    return len(times)


def register_routes(app):

    @app.context_processor
    def inject_globals():
        state = SystemState.query.first()
        pending_admin_count = PendingApproval.query.filter_by(status="PENDING_ADMIN").count()
        pending_access_count = AccessRequest.query.filter_by(status="PENDING").count() + IntegrationAccessRequest.query.filter_by(status="PENDING").count()
        return dict(system_locked=bool(state and state.lockdown), pending_admin_count=pending_admin_count, pending_access_count=pending_access_count)

    # ---------------------------------------------------------------- home
    @app.route("/")
    def index():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    # ---------------------------------------- device signals API endpoint
    @app.route("/api/device-signals", methods=["POST"])
    def device_signals():
        """Receive device signals from JavaScript and generate enhanced fingerprint."""
        try:
            signals = request.get_json()
            if not signals:
                return jsonify({"error": "No signals provided"}), 400
            
            # Create normalized string from signals
            signal_string = json.dumps(signals, sort_keys=True)
            
            # Generate SHA-256 hash as enhanced fingerprint
            enhanced_fingerprint = hashlib.sha256(signal_string.encode()).hexdigest()
            
            # Generate a human-readable device ID
            device_id = "DEV-" + enhanced_fingerprint[:8].upper()
            
            # Store in session for later use
            session["enhanced_fingerprint"] = enhanced_fingerprint
            session["device_id"] = device_id
            session["device_signals"] = signals
            
            return jsonify({
                "device_id": device_id,
                "fingerprint": enhanced_fingerprint[:16] + "..."
            })
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    # ------------------------------------------------------------ register
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form["username"].strip()
            email = request.form["email"].strip()
            password = request.form["password"]

            if User.query.filter_by(username=username).first():
                flash("Username already exists.", "danger")
                return redirect(url_for("register"))
            if User.query.filter_by(email=email).first():
                flash("Email already registered.", "danger")
                return redirect(url_for("register"))

            user = User(username=username, email=email, role="user")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html")

    # --------------------------------------------------------------- login
    @app.route("/login", methods=["GET", "POST"])
    def login():
        state = SystemState.query.first()
        if state and state.lockdown:
            return render_template("lockdown.html", reason=state.lockdown_reason, since=state.lockdown_since)

        ip = request.remote_addr or "0.0.0.0"
        if is_ip_blocked(BlockedIP, ip):
            return render_template("blocked.html", ip=ip)

        if request.method == "POST":
            username = request.form["username"].strip()
            password = request.form["password"]
            user = User.query.filter_by(username=username).first()

            if user is None or not user.check_password(password):
                FAILED_ATTEMPTS.setdefault(username, []).append(datetime.utcnow())
                db.session.add(LoginLog(
                    username_attempted=username, ip_address=ip,
                    user_agent=request.headers.get("User-Agent", ""),
                    success=False, risk_level="N/A", decision="REJECTED_BAD_CREDENTIALS",
                ))
                write_audit_log(db, AuditLog, username=username, device_id="-", browser=request.headers.get("User-Agent", ""),
                                 ip_address=ip, country="-", auth_status="REJECTED_BAD_CREDENTIALS", risk_score=0)
                db.session.commit()
                flash("Invalid username or password.", "danger")
                return redirect(url_for("login"))

            # Credentials valid -> capture zero-trust context now, verify later
            user_agent = request.headers.get("User-Agent", "")
            fingerprint = compute_device_fingerprint(user_agent, request.headers.get("Accept-Language", ""), ip)
            location = simulate_geo_lookup(ip)

            if user.role == "admin":
                db.session.add(LoginLog(
                    user_id=user.id, username_attempted=user.username, ip_address=ip,
                    device_fingerprint=fingerprint, user_agent=user_agent, location=location,
                    success=True, risk_score=0, risk_level="LOW", decision="ALLOWED",
                ))
                write_audit_log(db, AuditLog, username=user.username, device_id=fingerprint, browser=user_agent,
                                ip_address=ip, country=location, auth_status="ALLOWED", risk_score=0)
                db.session.commit()
                session.clear()
                login_user(user)
                flash("Welcome, administrator.", "success")
                return redirect(url_for("dashboard"))

            otp = generate_otp()
            session["pending_user_id"] = user.id
            session["otp_code"] = otp
            session["otp_expires"] = (datetime.utcnow() + timedelta(seconds=Config.OTP_VALID_SECONDS)).isoformat()
            session["ctx_fingerprint"] = fingerprint
            session["ctx_ip"] = ip
            session["ctx_location"] = location
            session["ctx_user_agent"] = user_agent

            sent, msg = send_login_otp(Config, user, otp)
            if sent:
                flash(msg, "info")
            else:
                flash(f"[DEV FALLBACK - {msg}] Your login code: {otp}", "warning")
            return redirect(url_for("verify_otp"))

        return render_template("login.html")

    # ---------------------------------------------------------- verify OTP
    @app.route("/verify-otp", methods=["GET", "POST"])
    def verify_otp():
        user_id = session.get("pending_user_id")
        if not user_id:
            return redirect(url_for("login"))

        if request.method == "POST":
            code = request.form["otp"].strip()
            expires = datetime.fromisoformat(session.get("otp_expires"))

            if datetime.utcnow() > expires:
                flash("Verification code expired. Please log in again.", "danger")
                session.clear()
                return redirect(url_for("login"))

            if code != session.get("otp_code"):
                flash("Incorrect verification code.", "danger")
                return redirect(url_for("verify_otp"))

            user = User.query.get(user_id)
            ip = session.get("ctx_ip")
            user_agent = session.get("ctx_user_agent")
            fingerprint = session.get("ctx_fingerprint")
            location = session.get("ctx_location")

            # Log the successful OTP verification
            log = LoginLog(
                user_id=user.id, username_attempted=user.username, ip_address=ip,
                device_fingerprint=fingerprint, user_agent=user_agent, location=location,
                success=True, risk_score=0, risk_level="LOW",
                decision="AWAITING_ADMIN_APPROVAL",
            )
            db.session.add(log)
            db.session.commit()

            # Clear OTP session keys but keep context for access request
            for key in ("otp_code", "otp_expires"):
                session.pop(key, None)

            # Redirect to waiting for admin approval page
            return redirect(url_for("waiting_admin_approval"))

        return render_template("otp.html")

    # ---------------------------------------- waiting for admin approval
    @app.route("/waiting-admin-approval", methods=["GET", "POST"])
    def waiting_admin_approval():
        user_id = session.get("pending_user_id")
        if not user_id:
            return redirect(url_for("login"))
        
        user = User.query.get(user_id)
        if not user:
            return redirect(url_for("login"))

        if request.method == "POST":
            # User clicked "Request Access"
            ip = session.get("ctx_ip")
            user_agent = session.get("ctx_user_agent")
            fingerprint = session.get("enhanced_fingerprint") or session.get("ctx_fingerprint")
            device_id = session.get("device_id", "UNKNOWN")
            location = session.get("ctx_location")
            
            browser, os = extract_browser_info(user_agent)
            
            # Create access request with enhanced device fingerprint
            access_request = AccessRequest(
                user_id=user.id,
                username=user.username,
                email=user.email,
                ip_address=ip,
                mac_address=device_id,  # Store device ID instead of MAC address
                device_fingerprint=fingerprint,
                browser=browser,
                operating_system=os,
                location=location,
                status="PENDING",
                login_time=datetime.utcnow(),
            )
            db.session.add(access_request)
            db.session.commit()
            
            # Generate and store approval code
            approval_code = generate_approval_code(8)
            code_hash = hash_approval_code(approval_code)
            approval_code_record = ApprovalCode(
                code_hash=code_hash,
                access_request_id=access_request.id,
                expires_at=datetime.utcnow() + timedelta(seconds=Config.OTP_VALID_SECONDS),
            )
            db.session.add(approval_code_record)
            db.session.commit()
            
            # Link approval code to request
            access_request.approval_code_id = approval_code_record.id
            db.session.commit()
            
            # Send email to administrator
            details = {
                "Username": user.username,
                "Email": user.email,
                "Login Time": access_request.login_time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "IP Address": ip,
                "Browser": browser,
                "Operating System": os,
                "MAC Address / Device Identifier": request.form.get("mac_address", "N/A"),
            }
            sent, msg = send_access_request_alert(Config, approval_code, details)
            if not sent:
                flash(f"[DEV FALLBACK - admin email not sent: {msg}] Admin approval code: {approval_code}", "warning")
            
            # Store request ID in session for polling
            session["access_request_id"] = access_request.id
            
            return redirect(url_for("waiting_approval_status"))
        
        return render_template("waiting_admin_approval.html", user=user)

    # ---------------------------------------- access request status polling
    @app.route("/waiting-approval-status")
    def waiting_approval_status():
        access_request_id = session.get("access_request_id")
        if not access_request_id:
            return redirect(url_for("login"))
        
        access_request = AccessRequest.query.get(access_request_id)
        if not access_request:
            return redirect(url_for("login"))
        
        return render_template("waiting_approval_status.html", request=access_request)

    @app.route("/api/access-request-status/<int:request_id>")
    def access_request_status(request_id):
        if session.get("access_request_id") != request_id:
            return jsonify({"status": "UNKNOWN"}), 403
        
        access_request = AccessRequest.query.get(request_id)
        if not access_request:
            return jsonify({"status": "UNKNOWN"}), 404
        
        return jsonify({"status": access_request.status})

    @app.route("/finalize-access-request/<int:request_id>")
    def finalize_access_request(request_id):
        if current_user.is_authenticated and current_user.role == "admin":
            flash("Request approved. The user must continue from their own waiting page.", "info")
            return redirect(url_for("admin_pending_requests"))

        if session.get("access_request_id") != request_id:
            return redirect(url_for("login"))
        
        access_request = AccessRequest.query.get(request_id)
        if not access_request:
            return redirect(url_for("login"))
        
        if access_request.status == "APPROVED":
            # Create active session with device fingerprint as primary identifier
            session_id = "".join(random.choices(string.ascii_letters + string.digits, k=64))
            device_id = session.get("device_id", access_request.mac_address)
            active_session = ActiveSession(
                session_id=session_id,
                user_id=access_request.user_id,
                username=access_request.username,
                email=access_request.email,
                mac_address=device_id,  # Device ID instead of MAC address
                device_fingerprint=access_request.device_fingerprint,
                ip_address=access_request.ip_address,
                browser=access_request.browser,
                operating_system=access_request.operating_system,
                status="ACTIVE",
                approved_by=access_request.approved_by,
                approval_time=access_request.approved_at,
            )
            db.session.add(active_session)
            db.session.commit()
            
            # Clear session and login user
            session.pop("access_request_id", None)
            session.pop("pending_user_id", None)
            session.pop("ctx_fingerprint", None)
            session.pop("ctx_ip", None)
            session.pop("ctx_location", None)
            session.pop("ctx_user_agent", None)
            
            user = User.query.get(access_request.user_id)
            login_user(user)
            
            flash("Access approved. Welcome to CloudSentinel.", "success")
            return redirect(url_for("dashboard"))
        
        if access_request.status == "DENIED":
            session.clear()
            flash("Access request was denied by the administrator.", "danger")
            return redirect(url_for("login"))
        
        return redirect(url_for("waiting_approval_status"))

    # --------------------------------------------------- user device approval
    @app.route("/device-approval", methods=["GET", "POST"])
    def device_approval():
        approval_id = session.get("pending_approval_id")
        if not approval_id:
            return redirect(url_for("login"))
        approval = PendingApproval.query.get(approval_id)
        if approval is None or approval.status not in ("PENDING_USER",):
            return redirect(url_for("waiting_approval"))

        if request.method == "POST":
            code = request.form["otp"].strip()
            approval.user_attempts += 1

            if datetime.utcnow() > approval.user_otp_expires or approval.user_attempts > 5:
                approval.status = "DENIED"
                db.session.commit()
                record_denial_and_escalate(db, MODELS, Config, approval.ip_address, approval.user.username, "user approval code expired/too many attempts")
                write_audit_log(db, AuditLog, username=approval.user.username, device_id=approval.device_fingerprint,
                                 browser=approval.user_agent, ip_address=approval.ip_address, country=approval.location,
                                 auth_status="DENIED_USER_OTP", risk_score=approval.risk_score, admin_decision="N/A")
                send_denial_notice(Config, approval.user, "verification code expired or too many incorrect attempts")
                session.clear()
                flash("Approval request denied and the session was blocked.", "danger")
                return redirect(url_for("login"))

            if code != approval.user_otp:
                db.session.commit()
                flash("Incorrect approval code.", "danger")
                return redirect(url_for("device_approval"))

            # User approved their own new-device login -> escalate to admin
            approval.user_approved = True
            approval.status = "PENDING_ADMIN"
            admin_otp = generate_otp()
            approval.admin_otp = admin_otp
            approval.admin_otp_expires = datetime.utcnow() + timedelta(seconds=Config.OTP_VALID_SECONDS)
            db.session.commit()

            write_audit_log(db, AuditLog, username=approval.user.username, device_id=approval.device_fingerprint,
                             browser=approval.user_agent, ip_address=approval.ip_address, country=approval.location,
                             auth_status="AWAITING_ADMIN_APPROVAL", risk_score=approval.risk_score)

            details = {
                "Username": approval.user.username,
                "Device": approval.user_agent,
                "IP Address": approval.ip_address,
                "Location": approval.location,
                "Login Time": approval.created_at.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "Risk Score": f"{approval.risk_score}/100 ({approval.risk_level})",
                "AI Behavior Analysis": f"anomaly={approval.ai_anomaly}, reasons: {approval.reasons or 'none'}",
            }
            sent, msg = send_admin_alert(Config, admin_otp, details)
            if not sent:
                flash(f"[DEV FALLBACK — admin email not sent: {msg}] Admin approval code: {admin_otp}", "warning")

            flash("Approved. Waiting for administrator confirmation now.", "info")
            return redirect(url_for("waiting_approval"))

        return render_template("device_approval.html", approval=approval)

    # ------------------------------------------------------- waiting screen
    @app.route("/waiting-approval")
    def waiting_approval():
        approval_id = session.get("pending_approval_id")
        if not approval_id:
            return redirect(url_for("login"))
        approval = PendingApproval.query.get(approval_id)
        if approval is None:
            return redirect(url_for("login"))
        return render_template("waiting_approval.html", approval=approval)

    @app.route("/api/approval-status/<int:approval_id>")
    def approval_status(approval_id):
        if session.get("pending_approval_id") != approval_id:
            return jsonify({"status": "UNKNOWN"}), 403
        approval = PendingApproval.query.get(approval_id)
        if approval is None:
            return jsonify({"status": "UNKNOWN"}), 404
        return jsonify({"status": approval.status})

    @app.route("/device-approval/finalize/<int:approval_id>")
    def finalize_approval(approval_id):
        if session.get("pending_approval_id") != approval_id:
            return redirect(url_for("login"))
        approval = PendingApproval.query.get(approval_id)
        if approval is None:
            return redirect(url_for("login"))

        if approval.status == "APPROVED":
            user = approval.user
            if not is_known_device(user, approval.device_fingerprint, Device):
                db.session.add(Device(user_id=user.id, fingerprint=approval.device_fingerprint, trusted=True))
                db.session.commit()
            session.pop("pending_approval_id", None)
            session.pop("pending_user_id", None)
            login_user(user)
            flash("New device approved by both you and the administrator. Access granted.", "success")
            return redirect(url_for("dashboard"))

        if approval.status == "DENIED":
            session.clear()
            flash("Access was denied by the administrator.", "danger")
            return redirect(url_for("login"))

        return redirect(url_for("waiting_approval"))

    # ---------------------------------------------------- admin approvals
    @app.route("/admin/approvals")
    @login_required
    def admin_approvals():
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        pending = PendingApproval.query.filter_by(status="PENDING_ADMIN").order_by(PendingApproval.created_at.desc()).all()
        return render_template("admin_approvals.html", approvals=pending)

    # ---------------------------------------- admin pending access requests
    @app.route("/admin/pending-requests")
    @login_required
    def admin_pending_requests():
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        pending = AccessRequest.query.filter_by(status="PENDING").order_by(AccessRequest.created_at.desc()).all()
        bookstream_pending = IntegrationAccessRequest.query.filter_by(status="PENDING").order_by(IntegrationAccessRequest.created_at.desc()).all()
        return render_template("admin_pending_requests.html", requests=pending, bookstream_requests=bookstream_pending)

    @app.route("/admin/pending-requests/<int:request_id>", methods=["GET", "POST"])
    @login_required
    def admin_request_detail(request_id):
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))

        access_request = AccessRequest.query.get_or_404(request_id)

        if request.method == "POST":
            decision = request.form.get("decision")
            code = request.form.get("approval_code", "").strip()

            if decision == "deny":
                access_request.status = "DENIED"
                db.session.commit()
                write_audit_log(db, AuditLog, username=access_request.username, device_id=access_request.device_fingerprint,
                                 browser=access_request.browser, ip_address=access_request.ip_address, country=access_request.location,
                                 auth_status="DENIED_BY_ADMIN", risk_score=0, admin_decision="DENIED")
                send_denial_notice(Config, access_request.user, "the administrator denied this access request")
                flash("Request denied.", "warning")
                return redirect(url_for("admin_pending_requests"))

            # Check for existing active session for this user with different device
            existing_session = ActiveSession.query.filter_by(
                user_id=access_request.user_id,
                status="ACTIVE"
            ).first()

            if existing_session:
                # Check if it's the same device (same device fingerprint)
                if existing_session.device_fingerprint == access_request.device_fingerprint:
                    # Same device - allow approval (renew session)
                    pass
                else:
                    # Different device - prevent approval
                    session_duration = datetime.utcnow() - existing_session.login_time
                    hours = int(session_duration.total_seconds() // 3600)
                    minutes = int((session_duration.total_seconds() % 3600) // 60)
                    
                    return render_template("admin_request_detail.html", 
                                          request=access_request,
                                          existing_session=existing_session,
                                          session_duration=f"{hours}h {minutes}m",
                                          error="User already has an active approved session on a different device.")

            # Verify approval code
            approval_code_record = ApprovalCode.query.get(access_request.approval_code_id)
            if not approval_code_record:
                flash("Invalid approval code record.", "danger")
                return redirect(url_for("admin_pending_requests"))

            if datetime.utcnow() > approval_code_record.expires_at:
                access_request.status = "DENIED"
                db.session.commit()
                flash("Approval code has expired. Request denied.", "danger")
                return redirect(url_for("admin_pending_requests"))

            if approval_code_record.used:
                access_request.status = "DENIED"
                db.session.commit()
                flash("Approval code has already been used. Request denied.", "danger")
                return redirect(url_for("admin_pending_requests"))

            if not verify_approval_code(code, approval_code_record.code_hash):
                flash("Incorrect approval code.", "danger")
                return render_template("admin_request_detail.html", request=access_request, error="Incorrect approval code.")

            # Code is valid - approve the request
            approval_code_record.used = True
            access_request.status = "APPROVED"
            access_request.approved_by = current_user.id
            access_request.approved_at = datetime.utcnow()
            db.session.commit()

            write_audit_log(db, AuditLog, username=access_request.username, device_id=access_request.device_fingerprint,
                             browser=access_request.browser, ip_address=access_request.ip_address, country=access_request.location,
                             auth_status="APPROVED", risk_score=0, admin_decision="APPROVED")

            flash(f"Access approved for '{access_request.username}'.", "success")
            return redirect(url_for("admin_pending_requests"))

        # Check for existing session on GET request
        existing_session = ActiveSession.query.filter_by(
            user_id=access_request.user_id,
            status="ACTIVE"
        ).first()
        
        session_duration_str = None
        if existing_session:
            session_duration = datetime.utcnow() - existing_session.login_time
            hours = int(session_duration.total_seconds() // 3600)
            minutes = int((session_duration.total_seconds() % 3600) // 60)
            session_duration_str = f"{hours}h {minutes}m"

        return render_template("admin_request_detail.html", 
                              request=access_request,
                              existing_session=existing_session,
                              session_duration=session_duration_str)

    @app.route("/admin/terminate-session/<int:session_id>", methods=["POST"])
    @login_required
    def terminate_session(session_id):
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))

        active_session = ActiveSession.query.get_or_404(session_id)
        active_session.status = "TERMINATED"
        db.session.commit()

        flash(f"Session terminated for user '{active_session.username}'.", "success")
        # Check if called from request detail or sessions page
        if request.referrer and 'pending-requests' in request.referrer:
            return redirect(request.referrer)
        return redirect(url_for("admin_active_sessions"))

    # ---------------------------------------- admin active sessions monitor
    @app.route("/admin/active-sessions")
    @login_required
    def admin_active_sessions():
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        
        # Get filter parameters
        search = request.args.get('search', '').strip()
        status_filter = request.args.get('status', 'ACTIVE')
        
        query = ActiveSession.query
        
        if status_filter == 'ACTIVE':
            query = query.filter_by(status='ACTIVE').filter(ActiveSession.last_activity >= datetime.utcnow() - timedelta(minutes=2))
        elif status_filter != 'all':
            query = query.filter_by(status=status_filter)
        
        if search:
            query = query.filter(
                (ActiveSession.username.ilike(f'%{search}%')) |
                (ActiveSession.email.ilike(f'%{search}%')) |
                (ActiveSession.ip_address.ilike(f'%{search}%')) |
                (ActiveSession.mac_address.ilike(f'%{search}%'))
            )
        
        sessions = query.order_by(ActiveSession.login_time.desc()).all()
        return render_template("admin_active_sessions.html", sessions=sessions, search=search, status_filter=status_filter, active_cutoff=datetime.utcnow() - timedelta(minutes=2))

    @app.post("/api/session-heartbeat")
    @login_required
    def session_heartbeat():
        active_session = ActiveSession.query.filter_by(user_id=current_user.id, status="ACTIVE").order_by(ActiveSession.last_activity.desc()).first()
        if active_session:
            active_session.last_activity = datetime.utcnow()
            db.session.commit()
        return jsonify({"active": bool(active_session)})

    @app.route("/admin/approvals/<int:approval_id>", methods=["GET", "POST"])
    @login_required
    def admin_approval_detail(approval_id):
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))

        approval = PendingApproval.query.get_or_404(approval_id)

        if request.method == "POST":
            decision = request.form.get("decision")
            code = request.form.get("otp", "").strip()
            approval.admin_attempts += 1

            if decision == "deny":
                approval.status = "DENIED"
                db.session.commit()
                record_denial_and_escalate(db, MODELS, Config, approval.ip_address, approval.user.username, "denied by administrator")
                write_audit_log(db, AuditLog, username=approval.user.username, device_id=approval.device_fingerprint,
                                 browser=approval.user_agent, ip_address=approval.ip_address, country=approval.location,
                                 auth_status="DENIED_BY_ADMIN", risk_score=approval.risk_score, admin_decision="DENIED")
                send_denial_notice(Config, approval.user, "the administrator denied this new-device request")
                flash("Request denied.", "warning")
                return redirect(url_for("admin_approvals"))

            if datetime.utcnow() > approval.admin_otp_expires or approval.admin_attempts > 5:
                approval.status = "DENIED"
                db.session.commit()
                record_denial_and_escalate(db, MODELS, Config, approval.ip_address, approval.user.username, "admin approval code expired/too many attempts")
                write_audit_log(db, AuditLog, username=approval.user.username, device_id=approval.device_fingerprint,
                                 browser=approval.user_agent, ip_address=approval.ip_address, country=approval.location,
                                 auth_status="DENIED_ADMIN_OTP", risk_score=approval.risk_score, admin_decision="DENIED")
                flash("Approval code expired or too many attempts — request denied.", "danger")
                return redirect(url_for("admin_approvals"))

            if code != approval.admin_otp:
                db.session.commit()
                flash("Incorrect administrator approval code.", "danger")
                return redirect(url_for("admin_approval_detail", approval_id=approval.id))

            approval.admin_approved = True
            approval.status = "APPROVED"
            db.session.commit()
            write_audit_log(db, AuditLog, username=approval.user.username, device_id=approval.device_fingerprint,
                             browser=approval.user_agent, ip_address=approval.ip_address, country=approval.location,
                             auth_status="APPROVED", risk_score=approval.risk_score, admin_decision="APPROVED")
            flash(f"Approved. Device trusted for '{approval.user.username}'.", "success")
            return redirect(url_for("admin_approvals"))

        return render_template("admin_approval_detail.html", approval=approval)

    # ------------------------------------------------ manage login logs
    @app.route("/admin/login-logs")
    @login_required
    def admin_login_logs():
        """View all login logs with edit/delete options"""
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        
        page = request.args.get('page', 1, type=int)
        logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).paginate(page=page, per_page=20)
        return render_template("admin_login_logs.html", logs=logs)

    @app.route("/admin/login-logs/<int:log_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_login_log(log_id):
        """Edit a login log"""
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        
        log = LoginLog.query.get_or_404(log_id)
        
        if request.method == "POST":
            # Update editable fields
            log.location = request.form.get("location", log.location)
            log.risk_level = request.form.get("risk_level", log.risk_level)
            log.risk_score = float(request.form.get("risk_score", log.risk_score))
            log.decision = request.form.get("decision", log.decision)
            log.success = request.form.get("success") == "on"
            
            db.session.commit()
            flash("Login log updated successfully.", "success")
            return redirect(url_for("admin_login_logs"))
        
        return render_template("edit_login_log.html", log=log)

    @app.route("/admin/login-logs/<int:log_id>/delete", methods=["POST"])
    @login_required
    def delete_login_log(log_id):
        """Delete a login log"""
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        
        log = LoginLog.query.get_or_404(log_id)
        db.session.delete(log)
        db.session.commit()
        flash("Login log deleted successfully.", "success")
        return redirect(url_for("admin_login_logs"))

    @app.route("/admin/login-logs/delete-multiple", methods=["POST"])
    @login_required
    def delete_multiple_login_logs():
        """Delete multiple login logs at once"""
        if current_user.role != "admin":
            return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
        log_ids = request.form.getlist("log_ids")
        if log_ids:
            LoginLog.query.filter(LoginLog.id.in_(log_ids)).delete(synchronize_session=False)
            db.session.commit()
            flash(f"{len(log_ids)} login logs deleted successfully.", "success")
        
        return redirect(url_for("admin_login_logs"))

    # ------------------------------------------------ manage approvals
    @app.route("/admin/all-approvals")
    @login_required
    def admin_all_approvals():
        """View all approvals (pending and completed) with edit/delete options"""
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        
        page = request.args.get('page', 1, type=int)
        status_filter = request.args.get('status', 'all')
        
        query = PendingApproval.query
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)
        
        approvals = query.order_by(PendingApproval.created_at.desc()).paginate(page=page, per_page=20)
        return render_template("admin_all_approvals.html", approvals=approvals, status_filter=status_filter)

    @app.route("/admin/approvals/<int:approval_id>/edit", methods=["GET", "POST"])
    @login_required
    def edit_approval(approval_id):
        """Edit an approval request"""
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        
        approval = PendingApproval.query.get_or_404(approval_id)
        
        if request.method == "POST":
            # Update editable fields
            approval.location = request.form.get("location", approval.location)
            approval.risk_level = request.form.get("risk_level", approval.risk_level)
            approval.risk_score = float(request.form.get("risk_score", approval.risk_score))
            approval.status = request.form.get("status", approval.status)
            approval.ai_anomaly = float(request.form.get("ai_anomaly", approval.ai_anomaly))
            approval.reasons = request.form.get("reasons", approval.reasons)
            
            db.session.commit()
            flash("Approval request updated successfully.", "success")
            return redirect(url_for("admin_all_approvals"))
        
        return render_template("edit_approval.html", approval=approval)

    @app.route("/admin/approvals/<int:approval_id>/delete", methods=["POST"])
    @login_required
    def delete_approval(approval_id):
        """Delete an approval request"""
        if current_user.role != "admin":
            flash("Administrator access required.", "danger")
            return redirect(url_for("dashboard"))
        
        approval = PendingApproval.query.get_or_404(approval_id)
        db.session.delete(approval)
        db.session.commit()
        flash("Approval request deleted successfully.", "success")
        return redirect(url_for("admin_all_approvals"))

    @app.route("/admin/approvals/delete-multiple", methods=["POST"])
    @login_required
    def delete_multiple_approvals():
        """Delete multiple approval requests at once"""
        if current_user.role != "admin":
            return jsonify({"status": "error", "message": "Unauthorized"}), 403
        
        approval_ids = request.form.getlist("approval_ids")
        if approval_ids:
            PendingApproval.query.filter(PendingApproval.id.in_(approval_ids)).delete(synchronize_session=False)
            db.session.commit()
            flash(f"{len(approval_ids)} approval requests deleted successfully.", "success")
        
        return redirect(url_for("admin_all_approvals"))

    # ------------------------------------------------------------ honeypot
    @app.route("/honeypot")
    def honeypot():
        return render_template("honeypot.html")

    @app.route("/honeypot/log-action", methods=["POST"])
    def honeypot_log_action():
        ip = request.remote_addr or "0.0.0.0"
        action = request.json.get("action", "unknown interaction") if request.is_json else "unknown interaction"
        db.session.add(HoneypotLog(ip_address=ip, username_attempted=str(session.get("pending_user_id", "unknown")), action=action))
        db.session.commit()
        return jsonify({"status": "ok"})

    # ---------------------------------------------------------- lockdown
    @app.route("/lockdown")
    def lockdown_page():
        state = SystemState.query.first()
        return render_template("lockdown.html", reason=state.lockdown_reason if state else "", since=state.lockdown_since if state else None)

    @app.route("/admin/lockdown/release", methods=["POST"])
    @login_required
    def release_lockdown():
        if current_user.role != "admin":
            flash("Only administrators may release lockdown.", "danger")
            return redirect(url_for("dashboard"))
        state = SystemState.query.first()
        if state:
            state.lockdown = False
            state.lockdown_reason = None
            state.lockdown_since = None
            db.session.commit()
        flash("Emergency lockdown released.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/admin/lockdown/engage", methods=["POST"])
    @login_required
    def engage_lockdown():
        if current_user.role != "admin":
            flash("Only administrators may engage lockdown.", "danger")
            return redirect(url_for("dashboard"))
        state = SystemState.query.first()
        if state is None:
            state = SystemState()
            db.session.add(state)
        state.lockdown = True
        state.lockdown_reason = "Manually engaged by administrator"
        state.lockdown_since = datetime.utcnow()
        db.session.commit()
        flash("Emergency lockdown engaged.", "warning")
        return redirect(url_for("dashboard"))

    # -------------------------------------------------------------- logout
    @app.route("/logout")
    @login_required
    def logout():
        # Terminate active session if exists
        active_session = ActiveSession.query.filter_by(
            user_id=current_user.id,
            status="ACTIVE"
        ).first()
        if active_session:
            active_session.status = "TERMINATED"
            db.session.commit()
        
        logout_user()
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("login"))

    # ------------------------------------------------------------ dashboard
    @app.before_request
    def continuous_ai_monitoring():
        """
        Lightweight continuous verification: if an authenticated session's
        live device fingerprint no longer matches the one captured at
        login time, treat it as abnormal mid-session activity and force
        re-authentication rather than silently trusting the session forever.
        Also updates last_activity timestamp for active sessions.
        """
        if current_user.is_authenticated and request.endpoint not in (
            "logout", "static", "login", "verify_otp", "device_approval",
            "waiting_approval", "approval_status", "finalize_approval",
            "waiting_admin_approval", "waiting_approval_status", "access_request_status",
            "finalize_access_request",
        ):
            # Update last activity for active session
            active_session = ActiveSession.query.filter_by(
                user_id=current_user.id,
                status="ACTIVE"
            ).first()
            if active_session:
                active_session.last_activity = datetime.utcnow()
                db.session.commit()
            
            live_fp = compute_device_fingerprint(
                request.headers.get("User-Agent", ""),
                request.headers.get("Accept-Language", ""),
                request.remote_addr or "0.0.0.0",
            )
            login_fp = session.get("ctx_fingerprint")
            if login_fp and live_fp != login_fp:
                # Terminate active session if exists
                if active_session:
                    active_session.status = "TERMINATED"
                    db.session.commit()
                logout_user()
                session.clear()
                flash("Session ended: device characteristics changed mid-session. Please log in again.", "warning")
                return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        logs = LoginLog.query.order_by(LoginLog.timestamp.desc()).limit(50).all()
        threats = ThreatLog.query.order_by(ThreatLog.timestamp.desc()).limit(50).all()
        honeypot_logs = HoneypotLog.query.order_by(HoneypotLog.timestamp.desc()).limit(50).all()
        audit_logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
        pending_approvals = PendingApproval.query.filter(PendingApproval.status.in_(["PENDING_USER", "PENDING_ADMIN"])).order_by(PendingApproval.created_at.desc()).all()
        blocked_ips = BlockedIP.query.order_by(BlockedIP.blocked_since.desc()).limit(20).all()
        replica = ReplicaStatus.query.first()
        state = SystemState.query.first()

        total_logins = LoginLog.query.filter_by(success=True).count()
        high_risk_count = LoginLog.query.filter_by(risk_level="HIGH").count()
        medium_risk_count = LoginLog.query.filter_by(risk_level="MEDIUM").count()
        low_risk_count = LoginLog.query.filter_by(risk_level="LOW").count()
        active_devices = Device.query.count()

        return render_template(
            "dashboard.html", user=current_user, logs=logs, threats=threats,
            honeypot_logs=honeypot_logs, audit_logs=audit_logs,
            pending_approvals=pending_approvals, blocked_ips=blocked_ips,
            replica=replica, state=state, total_logins=total_logins,
            high_risk_count=high_risk_count, medium_risk_count=medium_risk_count,
            low_risk_count=low_risk_count, active_devices=active_devices,
        )

    @app.route("/api/dashboard-data")
    @login_required
    def dashboard_data():
        low = LoginLog.query.filter_by(risk_level="LOW").count()
        medium = LoginLog.query.filter_by(risk_level="MEDIUM").count()
        high = LoginLog.query.filter_by(risk_level="HIGH").count()
        return jsonify({"low": low, "medium": medium, "high": high})


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get('PORT', '8000')))
