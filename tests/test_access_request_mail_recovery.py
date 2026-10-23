import os
import unittest

os.environ.setdefault("CS_DATABASE_URI", "sqlite:///:memory:")

import app as app_module
from extensions import db
from models import AccessRequest, ActiveSession, ApprovalCode, SystemState, User


class AccessRequestMailRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.app = app_module.app
        self.app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
        self.client = self.app.test_client()
        self.admin_client = self.app.test_client()

        with self.app.app_context():
            db.drop_all()
            db.create_all()
            db.session.add(SystemState(lockdown=False))
            admin = User(username="admin", email="admin@example.com", role="admin")
            admin.set_password("Admin@123")
            db.session.add(admin)
            db.session.commit()

    def _register_user(self):
        return self.client.post(
            "/register",
            data={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "UserPass123!",
            },
            follow_redirects=True,
        )

    def _login_user_until_access_request(self, access_mailer):
        captured = {}

        def fake_login_otp(_cfg, _user, otp):
            captured["login_otp"] = otp
            return True, "sent"

        original_login_otp = app_module.send_login_otp
        original_access_mailer = app_module.send_access_request_alert
        app_module.send_login_otp = fake_login_otp
        app_module.send_access_request_alert = access_mailer
        try:
            self._register_user()
            self.client.post(
                "/login",
                data={"username": "newuser", "password": "UserPass123!"},
                follow_redirects=True,
            )
            self.client.post(
                "/verify-otp",
                data={"otp": captured["login_otp"]},
                follow_redirects=True,
            )
            self.client.post("/waiting-admin-approval", follow_redirects=True)
        finally:
            app_module.send_login_otp = original_login_otp
            app_module.send_access_request_alert = original_access_mailer

    def _login_admin(self):
        self.admin_client.post(
            "/login",
            data={"username": "admin", "password": "Admin@123"},
            follow_redirects=True,
        )

    def test_failed_admin_mail_is_recoverable_and_approval_flow_completes(self):
        self._login_user_until_access_request(
            lambda _cfg, _code, _details: (False, "SMTP auth failed")
        )

        with self.app.app_context():
            request = AccessRequest.query.filter_by(username="newuser").one()
            self.assertEqual(request.status, "MAIL_FAILED")
            self.assertIsNone(request.approval_code_id)
            self.assertEqual(ApprovalCode.query.count(), 0)
            request_id = request.id

        self._login_admin()
        response = self.admin_client.get("/admin/pending-requests")
        self.assertIn(b"Email failed", response.data)

        self.admin_client.post(
            f"/admin/pending-requests/{request_id}",
            data={"decision": "approve", "approval_code": "bad-code"},
            follow_redirects=True,
        )
        with self.app.app_context():
            request = db.session.get(AccessRequest, request_id)
            self.assertEqual(request.status, "MAIL_FAILED")
            self.assertIsNone(request.approval_code_id)

        captured = {}

        def resend_success(_cfg, approval_code, _details):
            captured["approval_code"] = approval_code
            return True, "sent"

        original_access_mailer = app_module.send_access_request_alert
        app_module.send_access_request_alert = resend_success
        try:
            self.admin_client.post(
                f"/admin/pending-requests/{request_id}",
                data={"decision": "resend"},
                follow_redirects=True,
            )
        finally:
            app_module.send_access_request_alert = original_access_mailer

        with self.app.app_context():
            request = db.session.get(AccessRequest, request_id)
            self.assertEqual(request.status, "PENDING")
            self.assertIsNotNone(request.approval_code_id)
            self.assertEqual(ApprovalCode.query.count(), 1)

        self.admin_client.post(
            f"/admin/pending-requests/{request_id}",
            data={"decision": "approve", "approval_code": captured["approval_code"]},
            follow_redirects=True,
        )

        with self.app.app_context():
            request = db.session.get(AccessRequest, request_id)
            self.assertEqual(request.status, "APPROVED")
            self.assertEqual(ApprovalCode.query.count(), 0)
            self.assertEqual(ActiveSession.query.filter_by(username="newuser", status="ACTIVE").count(), 1)

        status_response = self.client.get(f"/api/access-request-status/{request_id}")
        self.assertEqual(status_response.get_json()["status"], "APPROVED")

        final_response = self.client.get(
            f"/finalize-access-request/{request_id}",
            follow_redirects=True,
        )
        self.assertIn(b"Security Dashboard", final_response.data)

    def test_second_device_with_same_credentials_requires_admin_to_terminate_active_session(self):
        captured = {}

        def first_login_otp(_cfg, _user, otp):
            captured["first_login_otp"] = otp
            return True, "sent"

        def first_access_mail(_cfg, approval_code, _details):
            captured["first_approval_code"] = approval_code
            return True, "sent"

        original_login_otp = app_module.send_login_otp
        original_access_mailer = app_module.send_access_request_alert
        app_module.send_login_otp = first_login_otp
        app_module.send_access_request_alert = first_access_mail
        try:
            self._register_user()
            self.client.post(
                "/login",
                data={"username": "newuser", "password": "UserPass123!"},
                follow_redirects=True,
            )
            self.client.post(
                "/verify-otp",
                data={"otp": captured["first_login_otp"]},
                follow_redirects=True,
            )
            self.client.post("/waiting-admin-approval", follow_redirects=True)
        finally:
            app_module.send_login_otp = original_login_otp
            app_module.send_access_request_alert = original_access_mailer

        with self.app.app_context():
            first_request_id = AccessRequest.query.filter_by(username="newuser").one().id

        self._login_admin()
        self.admin_client.post(
            f"/admin/pending-requests/{first_request_id}",
            data={"decision": "approve", "approval_code": captured["first_approval_code"]},
            follow_redirects=True,
        )
        self.client.get(
            f"/finalize-access-request/{first_request_id}",
            follow_redirects=True,
        )

        second_client = self.app.test_client()

        def second_login_otp(_cfg, _user, otp):
            captured["second_login_otp"] = otp
            return True, "sent"

        def second_access_mail(_cfg, approval_code, _details):
            captured["second_approval_code"] = approval_code
            captured["second_details"] = _details
            return True, "sent"

        app_module.send_login_otp = second_login_otp
        app_module.send_access_request_alert = second_access_mail
        try:
            second_client.post(
                "/login",
                data={"username": "newuser", "password": "UserPass123!"},
                headers={"User-Agent": "DifferentDeviceBrowser/1.0"},
                follow_redirects=True,
            )
            second_client.post(
                "/verify-otp",
                data={"otp": captured["second_login_otp"]},
                headers={"User-Agent": "DifferentDeviceBrowser/1.0"},
                follow_redirects=True,
            )
            second_client.post(
                "/waiting-admin-approval",
                headers={"User-Agent": "DifferentDeviceBrowser/1.0"},
                follow_redirects=True,
            )
        finally:
            app_module.send_login_otp = original_login_otp
            app_module.send_access_request_alert = original_access_mailer

        with self.app.app_context():
            second_request = AccessRequest.query.order_by(AccessRequest.id.desc()).first()
            second_request_id = second_request.id
            self.assertIn("Device Fingerprint", captured["second_details"])
            self.assertNotEqual(second_request.device_fingerprint, ActiveSession.query.filter_by(username="newuser", status="ACTIVE").one().device_fingerprint)

        response = self.admin_client.post(
            f"/admin/pending-requests/{second_request_id}",
            data={"decision": "approve", "approval_code": captured["second_approval_code"]},
            follow_redirects=True,
        )

        self.assertIn(b"active approved session", response.data)
        with self.app.app_context():
            second_request = db.session.get(AccessRequest, second_request_id)
            self.assertEqual(second_request.status, "PENDING")
            self.assertEqual(ActiveSession.query.filter_by(username="newuser", status="ACTIVE").count(), 1)


if __name__ == "__main__":
    unittest.main()
