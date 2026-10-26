# CloudSentinel
### Dual-Approval Zero-Trust Cloud Authentication System

CloudSentinel is a working prototype of a cloud authentication system
where **every new or suspicious login must be approved by both the
account owner AND the administrator** before access is granted — on
top of OTP authentication, continuous zero-trust verification, AI
behavior analysis, dynamic risk scoring, a decoy honeypot, simulated
hidden data replication, IP blocking, and emergency lockdown.

This project is intended as an educational / academic prototype (e.g.
for a project presentation or dissertation demo), not a
production-grade security product.

---

## 1. How It Works — Full Authentication Workflow

```
User Login (username + password)
        |
        v
Login OTP -> emailed to the account owner's OWN registered email
        |
        v
User enters login OTP
        |
        v
Zero-Trust Verification
(device fingerprint + IP + simulated geo-location + login hour
 + AI behavior anomaly score, via scikit-learn IsolationForest)
        |
        +-- Trusted device + low risk --------------> Full Dashboard Access
        |    (known device, known location, LOW risk)
        |
        +-- Unknown device / new location / abnormal behavior
                |
                v
        Approval OTP emailed to the ACCOUNT OWNER
        ("a new device is trying to access your account")
                |
                v
        Account owner enters that code to approve
                |
                v
        Alert + a SECOND OTP emailed to the ADMINISTRATOR,
        including: username, device info, IP, location,
        login time, risk score, AI behavior result
                |
                v
        Administrator reviews the request on the Security
        Dashboard and enters the administrator OTP
                |
        +-------+--------+
        v                v
    Approved          Denied / expired / too many attempts
        |                |
        v                v
  Device is now    Access blocked, both parties notified,
  trusted (no      threat logged, risk escalates. Repeated
  more approvals   denials from the same IP trigger:
  needed next        - temporary IP block
  time) + full        - honeypot decoy dashboard
  dashboard access    - simulated "freeze" of primary data
                       - simulated hidden replica activation
                       - automatic emergency lockdown
```

Every stage above is a real, running implementation — not just a
diagram — and was tested end-to-end (see §8). The "freeze primary
data," "activate hidden replica," and IP-block/honeypot/lockdown
actions are simulated in software (flags + logs in the database)
rather than wired to real cloud infrastructure, which is the
appropriate scope for an academic prototype — see §7 for how you'd
wire these to real infrastructure.

Once a device has been approved by both the user and the admin, it's
remembered as **trusted** — future logins from that same device (same
fingerprint) skip the dual-approval step entirely and go straight to
the dashboard after the login OTP, per the "reduce friction for known
devices" enhancement in the brief.

`admin` always bypasses dual-approval on its own account (an
administrator approving themselves would be circular) but every other
account goes through the full flow on any new device.

---

## 2. Technology Stack

| Layer               | Technology                                  |
|---------------------|----------------------------------------------|
| Backend framework   | Python 3 + Flask                             |
| Auth / sessions     | Flask-Login, Werkzeug password hashing       |
| Database (ORM)      | Flask-SQLAlchemy + SQLite (swap in MySQL/Postgres by changing `SQLALCHEMY_DATABASE_URI` in `config.py`) |
| Email delivery      | Python's built-in `smtplib` (no extra dependency) |
| AI behavior engine  | scikit-learn `IsolationForest`                |
| Frontend            | HTML, Bootstrap 5, Chart.js, vanilla JS       |

---

## 3. Project Structure

```
CloudSentinel/
|-- app.py                        # Flask app factory + all routes
|-- config.py                     # Config, risk weights, email/SMTP settings
|-- extensions.py                 # Flask-SQLAlchemy / Flask-Login instances
|-- models.py                     # User, Device, PendingApproval, AuditLog,
|                                  #   BlockedIP, LoginLog, ThreatLog, etc.
|-- requirements.txt
|-- security/
|   |-- ai_engine.py              # IsolationForest training + anomaly scoring
|   |-- zero_trust.py             # Device fingerprinting, geo simulation
|   |-- risk_engine.py            # Rule + AI combined risk scoring
|   |-- honeypot.py               # High-risk response: freeze/replica/lockdown
|   |-- dual_approval.py          # OTP generation, audit logging, escalation
|   `-- mailer.py                 # All outbound emails (login/approval/admin/denial)
|-- ml/
|   `-- train_model.py            # Standalone script to retrain the AI model
|-- templates/                    # Jinja2 HTML templates (Bootstrap themed)
|   |-- base.html, login.html, register.html, otp.html
|   |-- device_approval.html, waiting_approval.html
|   |-- admin_approvals.html, admin_approval_detail.html
|   `-- dashboard.html, honeypot.html, lockdown.html, blocked.html
|-- static/
|   |-- css/style.css
|   `-- js/dashboard.js
`-- instance/                     # SQLite database is created here at runtime
```

---

## 4. Setup & Run

```bash
cd CloudSentinel
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

pip install -r requirements.txt

python3 app.py
```

Open **http://127.0.0.1:5001** in your browser.

The database, tables, and a default admin account are created
automatically on first run:

```
username: admin
password: Admin@123
```

The AI model (`ml/behavior_model.pkl`) is also trained automatically on
first run if it doesn't already exist. To retrain it manually at any
time: `python3 ml/train_model.py`.

---

## 5. Setting Up Real Email Delivery (Recommended)

By default, no email is configured, so every OTP is shown directly on
screen with a "DEV FALLBACK" warning, so the app works out of the box
even with zero setup. To have real emails sent:

1. Use a Gmail account (or any SMTP provider) as the *sender*.
   For Gmail: enable 2-Step Verification, then create an
   [App Password](https://myaccount.google.com/apppasswords) and use
   that instead of your normal password.
2. Before running the app, set these environment variables:

   ```powershell
   # PowerShell
   $env:CS_MAIL_USERNAME = "your-sending-account@gmail.com"
   $env:CS_MAIL_PASSWORD = "your-16-character-app-password"
   $env:CS_ADMIN_EMAIL   = "admin-inbox-for-approval-alerts@gmail.com"
   python app.py
   ```
   ```bash
   # macOS/Linux
   export CS_MAIL_USERNAME="your-sending-account@gmail.com"
   export CS_MAIL_PASSWORD="your-16-character-app-password"
   export CS_ADMIN_EMAIL="admin-inbox-for-approval-alerts@gmail.com"
   python3 app.py
   ```

3. With this set:
   - **Login OTPs** go to each user's *own* registered email (the one
     they typed at registration).
   - **New-device approval OTPs** also go to the account owner's own
     email.
   - **Administrator alert + OTP** always goes to the single
     `CS_ADMIN_EMAIL` inbox you configured.
   - If sending ever fails (no internet, wrong password, etc.) the app
     automatically falls back to showing the code on screen with a
     warning, so you're never locked out during testing.

These settings also live in `config.py` under "Email (OTP delivery)"
if you'd rather hardcode them there — not recommended if you ever
share or commit this code, since it would expose your password.

---

## 6. Trying Out the Full Workflow

1. **Register** a new account (this uses the email you type as that
   account's real registered address).
2. **Log in** — you'll get a login OTP (on screen or by email).
3. Because it's a first-ever login, the device/location are unknown,
   so after the login OTP you're sent to **"Approve this device"** —
   another OTP is sent to your own email; enter it to confirm it's you.
4. This escalates to the **administrator**: log in as `admin` /
   `Admin@123` in a separate browser (or incognito window), open the
   Security Dashboard -> **Pending Approvals**, open the request, and
   you'll see the full context (device, IP, location, risk score, AI
   result) plus a field for the administrator's own OTP (shown on
   screen or emailed to `CS_ADMIN_EMAIL`).
5. Approve it — back in your original browser tab, the "waiting for
   approval" page auto-detects the approval and grants access.
6. **Log out and log back in** from the same browser — the device is
   now trusted, so you skip straight to the dashboard after the login
   OTP (no more dual approval needed for that device).
7. To see a **denial**, enter the wrong approval code repeatedly (or
   let it expire after 2 minutes) — this blocks the session, notifies
   both parties, and logs a threat. Enough denials from the same IP in
   a short window trigger an automatic **IP block**, and enough
   HIGH-risk/denial events trigger **emergency lockdown**, which an
   admin can release from the dashboard.

---

## 7. Where to Extend This for a Production System

- Replace `simulate_geo_lookup()` with a real MaxMind/IP-geolocation API.
- Replace the simulated "freeze primary / activate replica" flags in
  `security/honeypot.py` with real calls to your cloud provider's API
  (e.g. S3 bucket policy lockdown + cross-region replica promotion).
- Replace the fingerprint hash in `zero_trust.py` with a stronger
  client-side fingerprinting library (canvas/WebGL/TLS fingerprinting)
  for harder-to-spoof device identity.
- Swap SQLite for MySQL/PostgreSQL for multi-instance deployments (one
  line change in `config.py`).
- Add TLS termination (nginx/Caddy) and run behind a production WSGI
  server (gunicorn/uWSGI) instead of the Flask dev server — the Flask
  development server used here is not for production.
- Sign the "trusted device" record with a cryptographic device
  certificate/token (as suggested in the brief) instead of a plain
  fingerprint hash, so trust can't be spoofed by replaying a fingerprint.
- Expand the AI engine with richer behavioral telemetry (mouse/keyboard
  dynamics, API call sequences) and periodically retrain on real
  historical login data.

---

## 8. Testing Performed

This exact build was run end-to-end during development, including:
- Registration -> login OTP (emailed / on-screen fallback) -> unknown
  device -> user approval OTP -> admin alert + admin OTP -> approval ->
  dashboard access, with a live two-session test (regular user +
  separate admin session) confirming the full loop.
- Second login from the now-trusted device correctly skipping
  straight to the dashboard.
- A denial path (repeated wrong approval codes) correctly blocking the
  session, writing threat/audit log entries, and notifying the user.
- Dashboard rendering pending approvals, audit logs, threat logs, and
  risk-distribution charts from live data with no runtime errors.

No unresolved runtime errors were observed in any of the above flows.
