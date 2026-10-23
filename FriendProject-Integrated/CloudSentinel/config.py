import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    CLOUDSENTINEL_SERVICE_KEY = os.environ.get("CLOUDSENTINEL_SERVICE_KEY", "dev-integration-key")
    SECRET_KEY = os.environ.get("CLOUDSENTINEL_SECRET_KEY", "dev-secret-change-me")
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "instance", "cloudsentinel.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ---- Risk thresholds ----
    RISK_LOW_MAX = 30       # score <= 30  -> LOW
    RISK_MEDIUM_MAX = 60    # 30 < score <= 60 -> MEDIUM, above -> HIGH

    # ---- Rule based risk weights ----
    WEIGHT_NEW_DEVICE = 25
    WEIGHT_NEW_LOCATION = 20
    WEIGHT_UNUSUAL_HOUR = 10
    WEIGHT_FAILED_ATTEMPTS = 8       # per recent failed attempt (capped)
    WEIGHT_FAILED_ATTEMPTS_CAP = 32
    WEIGHT_RAPID_REQUESTS = 15
    AI_WEIGHT = 25                   # max contribution of the ML anomaly score

    # ---- Honeypot ----
    HONEYPOT_LOG_LIMIT = 200

    # ---- Emergency lockdown ----
    LOCKDOWN_HIGH_RISK_THRESHOLD = 3     # high-risk events within window triggers auto-lockdown
    LOCKDOWN_WINDOW_MINUTES = 10

    OTP_VALID_SECONDS = 120

    # ---- Email (OTP delivery) ----
    # For a Gmail account: enable 2-Step Verification, then create an
    # "App Password" (myaccount.google.com/apppasswords) and use that
    # here instead of your normal Gmail password.
    # You can either edit the values below directly, or set them as
    # environment variables before running the app (recommended so you
    # don't commit real credentials to any repo).
    MAIL_SERVER = os.environ.get("CS_MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("CS_MAIL_PORT", "587"))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get("CS_MAIL_USERNAME", "")       # the sending account's email
    MAIL_PASSWORD = os.environ.get("CS_MAIL_PASSWORD", "")       # the app password
    MAIL_SENDER_NAME = "CloudSentinel Security"

    # Every OTP is sent to this single fixed admin inbox (demo/testing mode)
    ADMIN_NOTIFY_EMAIL = os.environ.get("CS_ADMIN_EMAIL", "")
