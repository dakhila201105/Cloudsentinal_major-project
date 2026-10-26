"""Start the integrated CloudSentinel service with BookStream's shared key."""

import os
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
BOOKSTREAM_ENV = PROJECT_DIR.parent / "BookStream" / "backend" / ".env"
LOCAL_ENV = PROJECT_DIR / ".env"


def load_env_file(path, override_keys=()):
    """Read KEY=VALUE config; selected local settings may override shell values."""
    if not path.is_file():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key in override_keys:
            os.environ[key] = value
        elif key:
            os.environ.setdefault(key, value)


def read_service_key():
    if not BOOKSTREAM_ENV.is_file():
        raise RuntimeError("BookStream backend/.env was not found")
    for raw_line in BOOKSTREAM_ENV.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("CLOUDSENTINEL_SERVICE_KEY="):
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value:
                return value
    raise RuntimeError("CLOUDSENTINEL_SERVICE_KEY is missing from BookStream backend/.env")


load_env_file(LOCAL_ENV, override_keys={"CS_MAIL_USERNAME", "CS_MAIL_PASSWORD", "CS_ADMIN_EMAIL"})
load_env_file(BOOKSTREAM_ENV)
os.environ.setdefault("BOOKSTREAM_BACKEND_URL", f"http://127.0.0.1:{os.environ.get('PORT', '5001')}")
os.environ["CLOUDSENTINEL_SERVICE_KEY"] = read_service_key()
os.environ["PORT"] = "8000"

import app  # noqa: E402  (configuration must load after the shared key is set)

print(
    "CloudSentinel shared service-key config loaded:",
    app.app.config.get("CLOUDSENTINEL_SERVICE_KEY") == os.environ["CLOUDSENTINEL_SERVICE_KEY"],
)
app.app.run(debug=False, use_reloader=False, host="0.0.0.0", port=8000)
