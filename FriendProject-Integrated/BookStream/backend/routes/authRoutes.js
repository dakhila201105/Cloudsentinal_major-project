const express = require('express');
const router = express.Router();
const { register, login, getMe, logout, securityRequestStatus, completeSecurityRequest, verifyLoginOtp, resendLoginOtp } = require('../controllers/authController');
const { protect } = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.post('/dual-approval/:requestId/verify-user', verifyLoginOtp);
router.post('/dual-approval/:requestId/resend-user', resendLoginOtp);
router.get('/security-request/:requestId', securityRequestStatus);
router.post('/security-request/:requestId/complete', completeSecurityRequest);
router.get('/me', protect, getMe);
router.post('/logout', protect, logout);

module.exports = router;
