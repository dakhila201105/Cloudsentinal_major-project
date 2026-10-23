const express = require('express');
const router = express.Router();
const { register, login, getMe, logout, securityRequestStatus, completeSecurityRequest } = require('../controllers/authController');
const { protect } = require('../middleware/auth');

router.post('/register', register);
router.post('/login', login);
router.get('/security-request/:requestId', securityRequestStatus);
router.post('/security-request/:requestId/complete', completeSecurityRequest);
router.get('/me', protect, getMe);
router.post('/logout', protect, logout);

module.exports = router;
