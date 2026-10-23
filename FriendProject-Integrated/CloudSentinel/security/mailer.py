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

Every function returns (success: bool, message: str) and never raises —
if mail isn't configured or sending fails, the app falls back to
showing the code on screen so the demo keeps working end to end.
"""

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def _mail_ready(cfg):
    return bool(cfg.MAIL_USERNAME and cfg.MAIL_PASSWORD)


def _send(cfg, to_address, subject, text, html):
    if not _mail_ready(cfg):
        return False, "Email not configured (missing CS_MAIL_USERNAME / CS_MAIL_PASSWORD)."
    if not to_address:
        return False, "No destination email address on file."

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = f"{cfg.MAIL_SENDER_NAME} <{cfg.MAIL_USERNAME}>"
    msg["To"] = to_address
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(cfg.MAIL_SERVER, cfg.MAIL_PORT) as server:
            server.starttls(context=context)
            server.login(cfg.MAIL_USERNAME, cfg.MAIL_PASSWORD)
            server.sendmail(cfg.MAIL_USERNAME, [to_address], msg.as_string())
        return True, f"Email sent to {to_address}."
    except Exception as exc:
        return False, f"Failed to send email: {exc}"


def _code_html(heading, code, body_html, cfg):
    return f"""
    <div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;">
      <h2 style="color:#2563eb;">{heading}</h2>
      {body_html}
      <p style="font-size:28px;font-weight:bold;letter-spacing:4px;
                background:#111c34;color:#fff;padding:12px 20px;
                border-radius:8px;display:inline-block;">{code}</p>
      <p>This code expires in {cfg.OTP_VALID_SECONDS // 60} minutes.</p>
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
    return _send(cfg, cfg.ADMIN_NOTIFY_EMAIL, subject, text, html)


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
    details["username"] = details.get("Username", details.get("username"))
    subject = f"CloudSentinel ALERT — New Access Request ({details.get('username')})"
    details.pop("username", None)
    rows = "".join(f"<li><strong>{k}:</strong> {v}</li>" for k, v in details.items())
    text_rows = "\n".join(f"  {k}: {v}" for k, v in details.items())
    text = (
        f"A new access request is awaiting administrator approval.\n\n"
        f"{text_rows}\n\n"
        f"Administrator approval code: {approval_code}\n"
        f"It expires in {cfg.OTP_VALID_SECONDS // 60} minutes.\n\n"
        f"Review it on the Security Dashboard under Pending Requests."
    )
    html = _code_html(
        "New Access Request — Administrator Approval Required",
        approval_code,
        f"<p>A new access request is awaiting your approval:</p><ul>{rows}</ul>",
        cfg,
    )
    return _send(cfg, cfg.ADMIN_NOTIFY_EMAIL, subject, text, html)
