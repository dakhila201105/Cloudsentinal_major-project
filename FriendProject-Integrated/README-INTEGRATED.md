# CloudSentinel + BookStream Integrated Platform

This package connects the existing BookStream MERN application to the existing CloudSentinel Zero-Trust security platform.

## Services

- CloudSentinel: `http://127.0.0.1:8000`
- BookStream backend: `http://127.0.0.1:5001`
- BookStream frontend: `http://localhost:3000`
- MongoDB: `mongodb://127.0.0.1:27017/bookstream`

## Integration implemented

- BookStream registration creates a CloudSentinel security identity.
- BookStream login first verifies the registered email with a one-time code; a new code can be requested after two minutes.
- After email verification, every BookStream login waits for CloudSentinel administrator approval and a request-bound code emailed to the admin.
- User codes expire after two minutes; the request-bound admin code expires after ten minutes. Both are single-use, attempt-limited, and stored as keyed hashes.
- CloudSentinel records the requesting device ID and active sessions; approving a different device is blocked until the current active session is revoked.
- BookStream issues a JWT only after both approvals; each account has one active BookStream session at a time.
- Every protected BookStream request validates the CloudSentinel security session.
- Logout records an event and revokes the security session.
- Book views, searches, PDF downloads, bookmarks, ratings and admin book actions generate security telemetry.
- CloudSentinel stores real activity events and exposes user drill-down APIs.
- CloudSentinel has a real BookStream Security Intelligence dashboard with clickable users and live polling.
- CloudSentinel has BookStream Management for user freeze/unfreeze and book deletion through a server-to-server service key.
- IP-derived location is explicitly approximate.
- Passwords, hashes, JWT secrets and service keys are never displayed in the security dashboard.

## First-time setup

### 1. MongoDB

Install/start MongoDB locally.

### 2. CloudSentinel

```powershell
cd CloudSentinel
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Copy `.env.example` values into your environment. Use the same `CLOUDSENTINEL_SERVICE_KEY` in both projects.

Copy `.env.example` to `.env` and configure the SMTP sender credentials plus the administrator email. The local launcher loads this file and the BookStream backend `.env` (shell environment variables take precedence except that the shared service key is taken from BookStream's `.env`). Real email is required; codes are never displayed as a development fallback.

Start the integrated local service with the shared BookStream key:

```powershell
python start_local.py
```

Use only one CloudSentinel process on port 8000. The local launcher reads the service key from `BookStream\backend\.env` before starting Flask.

Default demo admin created by the existing project: `admin` / `Admin@123`. Change this before any non-demo use.

### 3. BookStream backend

```powershell
cd BookStream\backend
npm install
```

Create `.env`:

```env
MONGODB_URI=mongodb://127.0.0.1:27017/bookstream
JWT_SECRET=replace-with-a-long-random-secret
PORT=5001
CLOUDSENTINEL_URL=http://127.0.0.1:8000
CLOUDSENTINEL_SERVICE_KEY=the-same-service-key
```

Start:

```powershell
npm run dev
```

### 4. BookStream frontend

```powershell
cd BookStream\frontend
npm install
npm start
```

## Admin security console

Open CloudSentinel and sign in as the CloudSentinel administrator. From the main dashboard use:

- **BookStream Security Intelligence** for real users, activity, risk, events and approvals.
- **BookStream Management** for authorized user/book administration.

Clicking a user opens a security profile with events, sessions, devices, IPs, approximate locations, risk and anomaly values.

## Important architecture behavior

CloudSentinel is the security control plane; BookStream remains the protected application. The two databases are intentionally not merged. `bookstream_user_id` connects a BookStream identity to its CloudSentinel security identity.

The CloudSentinel SQLite replica/recovery features remain an academic prototype of cloud resilience, not a production disaster-recovery system.

## Validation

Python files were syntax-checked with `py_compile`. BookStream backend JavaScript files were checked with `node --check`. Full runtime validation requires local MongoDB, Python dependencies, Node dependencies and a running SMTP configuration if real email alerts are required.
