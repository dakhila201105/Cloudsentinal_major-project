"""Start the integrated CloudSentinel service with BookStream's shared key."""

import os
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent
BOOKSTREAM_ENV = PROJECT_DIR.parent / "BookStream" / "backend" / ".env"


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


os.environ["CLOUDSENTINEL_SERVICE_KEY"] = read_service_key()
os.environ["PORT"] = "8000"

import app  # noqa: E402  (configuration must load after the shared key is set)

print(
    "CloudSentinel shared service-key config loaded:",
    app.app.config.get("CLOUDSENTINEL_SERVICE_KEY") == os.environ["CLOUDSENTINEL_SERVICE_KEY"],
)
app.app.run(debug=False, use_reloader=False, host="0.0.0.0", port=8000)
