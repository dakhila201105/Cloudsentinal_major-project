"""
Mailer
-------
Sends authentication emails using standard library smtplib (no extra
dependency required):

  1. Login OTP           -> sent to the account owner's own registered email
  2. New-device approval -> sent to the account owner's email, asking them
                             to confirm a login from an unrecognized device
  3. Admin alert + OTP    -> sent to the fixed administrator inbox, with
                             full context of the suspicious login attempt

Every function returns (success: bool, message: str) and never raises.
The app should never display OTP values in the browser when delivery fails.
"""

import smtplib
import ssl
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _as_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _get_mail_setting(cfg, attr_name, env_name):
    value = os.environ.get(env_name) or getattr(cfg, attr_name, "")
    if value:
        setattr(cfg, attr_name, value)
    return value


def resolve_mail_config(cfg):
    mode = (os.environ.get("CS_MAIL_MODE") or getattr(cfg, "MAIL_MODE", "smtp")).strip().lower()
    username = _get_mail_setting(cfg, "MAIL_USERNAME", "CS_MAIL_USERNAME")
    password = _get_mail_setting(cfg, "MAIL_PASSWORD", "CS_MAIL_PASSWORD")
    server = _get_mail_setting(cfg, "MAIL_SERVER", "CS_MAIL_SERVER") or "smtp.gmail.com"
    port = int(_get_mail_setting(cfg, "MAIL_PORT", "CS_MAIL_PORT") or 587)
    use_tls = _as_bool(_get_mail_setting(cfg, "MAIL_USE_TLS", "CS_MAIL_USE_TLS") or True)
    admin_email = _get_mail_setting(cfg, "ADMIN_NOTIFY_EMAIL", "CS_ADMIN_EMAIL")
    sender_name = getattr(cfg, "MAIL_SENDER_NAME", "CloudSentinel Security")
    return {
        "mode": mode,
        "server": server,
        "port": port,
        "use_tls": use_tls,
        "username": username,
        "password": password,
        "sender_name": sender_name,
        "admin_email": admin_email,
        "ready": mode == "console" or bool(username and password),
    }


def _mail_ready(cfg):
    return resolve_mail_config(cfg)["ready"]


def _send(cfg, to_address, subject, text, html):
    mail = resolve_mail_config(cfg)
    if not to_address:
        return False, "No destination email address on file."
    if mail["mode"] == "console":
        print("\n" + "=" * 72)
        print("CloudSentinel console mail")
        print(f"To: {to_address}")
        print(f"Subject: {subject}")
        print("-" * 72)
        print(text)
        print("=" * 72 + "\n")
        return True, f"Console mail printed for {to_address}."
    if not mail["ready"]:
        return False, "Email not configured (missing CS_MAIL_USERNAME / CS_MAIL_PASSWORD)."

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{mail['sender_name']} <{mail['username']}>"
    msg["To"] = to_address
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        context = ssl.create_default_context()
        if mail["port"] == 465:
            server_ctx = smtplib.SMTP_SSL(mail["server"], mail["port"], context=context)
        else:
            server_ctx = smtplib.SMTP(mail["server"], mail["port"])

        with server_ctx as server:
            if mail["use_tls"] and mail["port"] != 465:
                server.starttls(context=context)
            server.login(mail["username"], mail["password"])
            server.sendmail(mail["username"], [to_address], msg.as_string())
        return True, f"Email sent to {to_address}."
    except Exception as exc:
        return False, f"Failed to send email: {exc}"


def send_test_email(cfg, to_address=None):
    mail = resolve_mail_config(cfg)
    destination = to_address or mail["admin_email"] or mail["username"]
    subject = "CloudSentinel - Mail authorization test"
    text = (
        "CloudSentinel mail authorization test succeeded.\n\n"
        "This confirms the configured sender account can authenticate with SMTP and send mail."
    )
    html = """
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;">
      <h2 style="color:#2563eb;">CloudSentinel Mail Test</h2>
      <p>Mail authorization succeeded.</p>
      <p style="color:#64748b;font-size:12px;">CloudSentinel automated security notice.</p>
    </div>
    """
    return _send(cfg, destination, subject, text, html)


def _expiry_minutes(cfg, expire_seconds=None):
    seconds = expire_seconds if expire_seconds is not None else cfg.OTP_VALID_SECONDS
    return max(1, int(seconds) // 60)


def _code_html(heading, code, body_html, cfg, expire_seconds=None):
    minutes = _expiry_minutes(cfg, expire_seconds)
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;">
      <h2 style="color:#2563eb;">{heading}</h2>
      {body_html}
      <p style="font-size:28px;font-weight:bold;letter-spacing:4px;
                background:#111c34;color:#fff;padding:12px 20px;
                border-radius:8px;display:inline-block;">{code}</p>
      <p>This code expires in {minutes} minutes.</p>
      <p style="color:#64748b;font-size:12px;">CloudSentinel automated security notice.</p>
    </div>
    """


def send_login_otp(cfg, user, otp_code):
    """Step 1: standard login OTP, sent to the account owner's own email."""
    subject = "CloudSentinel — Your login verification code"
    text = (
        f"Hi {user.username},\n\n"
        f"Your login verification code is: {otp_code}\n"
        f"It expires in {cfg.OTP_VALID_SECONDS // 60} minutes.\n\n"
        f"If you didn't request this, you can ignore this email."
    )
    html = _code_html(
        "Login Verification Code",
        otp_code,
        f"<p>Hi <strong>{user.username}</strong>, use this code to finish logging in.</p>",
        cfg,
    )
    return _send(cfg, user.email, subject, text, html)


def send_new_device_approval(cfg, user, otp_code, ip, location, device_summary):
    """Step 2: unknown/suspicious device — ask the account owner to approve it."""
    subject = "CloudSentinel — New device is trying to access your account"
    text = (
        f"Hi {user.username},\n\n"
        f"A login to your account was attempted from a device we don't recognize:\n"
        f"  IP address: {ip}\n"
        f"  Location:   {location}\n"
        f"  Device:     {device_summary}\n\n"
        f"If this was you, approve it by entering this code: {otp_code}\n"
        f"It expires in {cfg.OTP_VALID_SECONDS // 60} minutes.\n\n"
        f"If this WASN'T you, do not share this code — the request will simply expire."
    )
    html = _code_html(
        "New Device Access Request",
        otp_code,
        f"""<p>Hi <strong>{user.username}</strong>, a login was attempted from a device
        we don't recognize:</p>
        <ul>
          <li><strong>IP:</strong> {ip}</li>
          <li><strong>Location:</strong> {location}</li>
          <li><strong>Device:</strong> {device_summary}</li>
        </ul>
        <p>If this was you, enter this approval code to continue:</p>""",
        cfg,
    )
    return _send(cfg, user.email, subject, text, html)


def send_admin_alert(cfg, otp_code, details: dict):
    """Step 3: alert the administrator with full context + their own OTP."""
    subject = f"CloudSentinel ALERT — new-device login pending approval ({details.get('username')})"
    rows = "".join(f"<li><strong>{k}:</strong> {v}</li>" for k, v in details.items())
    text_rows = "\n".join(f"  {k}: {v}" for k, v in details.items())
    text = (
        f"A new-device login is awaiting administrator approval.\n\n"
        f"{text_rows}\n\n"
        f"Administrator approval code: {otp_code}\n"
        f"It expires in {cfg.OTP_VALID_SECONDS // 60} minutes.\n\n"
        f"Review it on the Security Dashboard under Pending Approvals."
    )
    html = _code_html(
        "Administrator Approval Required",
        otp_code,
        f"<p>A new-device login is awaiting your approval:</p><ul>{rows}</ul>",
        cfg,
    )
    return _send(cfg, resolve_mail_config(cfg)["admin_email"], subject, text, html)


def send_denial_notice(cfg, user, reason):
    """Notify the account owner that a login attempt was denied."""
    subject = "CloudSentinel — Login attempt denied"
    text = (
        f"Hi {user.username},\n\n"
        f"A login attempt on your account was denied.\nReason: {reason}\n\n"
        f"If this wasn't you, no further action is needed — the request has already been blocked."
    )
    html = _code_html(
        "Login Attempt Denied",
        "✕",
        f"<p>Hi <strong>{user.username}</strong>, a login attempt on your account was denied.</p><p>Reason: {reason}</p>",
        cfg,
    )
    return _send(cfg, user.email, subject, text, html)


def send_access_request_alert(cfg, approval_code, details: dict):
    """Send an email to the administrator with a new access request and approval code."""
    details = dict(details)
    username = details.get("Username", details.get("username"))
    subject = f"CloudSentinel ALERT — New Access Request ({username})"
    display = {k: v for k, v in details.items() if k.lower() != "username"}
    rows = "".join(f"<li><strong>{k}:</strong> {v}</li>" for k, v in display.items())
    text_rows = "\n".join(f"  {k}: {v}" for k, v in display.items())
    expire_seconds = getattr(cfg, "APPROVAL_CODE_VALID_SECONDS", cfg.OTP_VALID_SECONDS)
    minutes = _expiry_minutes(cfg, expire_seconds)
    text = (
        f"New Access Request\n\n"
        f"{text_rows}\n\n"
        f"Administrator approval code: {approval_code}\n"
        f"It expires in {minutes} minutes.\n\n"
        f"Review it on the Security Dashboard under Pending Requests."
        f" Do not share this code with the user."
    )
    html = _code_html(
        "New Access Request",
        approval_code,
        f"<p>A new access request is awaiting your approval:</p><ul>{rows}</ul>"
        f"<p>This one-time approval code is for the administrator only.</p>",
        cfg,
        expire_seconds=expire_seconds,
    )
    return _send(cfg, resolve_mail_config(cfg)["admin_email"], subject, text, html)
