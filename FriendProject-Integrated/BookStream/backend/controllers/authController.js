const jwt = require('jsonwebtoken');
const User = require('../models/User');
const cloudSentinel = require('../services/cloudSentinel');

// Generate JWT Token
const generateToken = (id, securitySessionId) => {
  return jwt.sign({ id, security_session_id: securitySessionId }, process.env.JWT_SECRET, {
    expiresIn: '30d',
  });
};

const syncCloudSentinelActivity = async (user, req, eventType) => {
  try {
    // Make sure the identity exists before posting its activity event.
    await cloudSentinel.registerUser(user);
    await cloudSentinel.event(user, req, eventType);
  } catch (error) {
    console.error(`CloudSentinel ${eventType} sync failed:`, error.response?.data || error.message);
  }
};

// @desc    Register new user
// @route   POST /api/auth/register
// @access  Public
const register = async (req, res) => {
  try {
    const { firstName, lastName, password } = req.body;
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';

    if (!firstName?.trim() || !lastName?.trim() || !email || !password) {
      return res.status(400).json({ message: 'First name, last name, email, and password are required' });
    }

    // Check if user exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      return res.status(400).json({ message: 'User already exists' });
    }

    // Determine role based on email (admin if ends with @admin.com)
    const role = email.endsWith('@admin.com') ? 'admin' : 'user';

    // Create user
    const user = await User.create({
      firstName,
      lastName,
      email,
      password,
      role,
    });

    if (user) {
      // CloudSentinel is supplemental; a temporary outage must not turn a saved
      // BookStream account into a reported registration failure.
      await syncCloudSentinelActivity(user, req, 'REGISTER');
      res.status(201).json({
        message: 'Registered successfully',
        user: {
          _id: user._id,
          firstName: user.firstName,
          lastName: user.lastName,
          email: user.email,
          role: user.role,
        },
      });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
const login = async (req, res) => {
  try {
    const email = typeof req.body.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const { password } = req.body;
    if (!email || typeof password !== 'string' || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }

    // Check for user
    const user = await User.findOne({ email });

    if (user && (await user.comparePassword(password))) {
      if (user.status !== 'ACTIVE') {
        try {
          await cloudSentinel.registerUser(user);
          const review = await cloudSentinel.evaluateLogin(user, req);
          if (review.status === 202 && review.data?.request_id) {
            return res.status(202).json({ ...review.data, message: 'This frozen account sign-in has been sent to an administrator for review.' });
          }
        } catch (error) {
          console.error('Frozen account review request failed:', error.response?.data || error.message);
        }
        return res.status(403).json({ code: 'ACCOUNT_RESTRICTED', message: 'Your BookStream account is frozen, so you have been signed out. Please contact the BookStream administrator if you believe this is a mistake. Your account will remain blocked until an administrator reviews it.' });
      }
      // Keep the local email/password check authoritative. Sync the identity
      // before recording login so later activity can be associated with it.
      let securitySessionId;
      try { await cloudSentinel.registerUser(user); securitySessionId = await cloudSentinel.startSession(user, req); }
      catch (error) { console.error('CloudSentinel session start failed:', error.response?.data || error.message); }
      await cloudSentinel.event(user, req, 'LOGIN', { session_id: securitySessionId });
      return res.json({ _id:user._id, firstName:user.firstName, lastName:user.lastName, email:user.email, role:user.role, security_session_id:securitySessionId, token:generateToken(user._id, securitySessionId) });
    } else {
      if (user) cloudSentinel.event(user, req, 'LOGIN_FAILED').catch(() => {});
      res.status(401).json({ message: 'Invalid email or password' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Get current user
// @route   GET /api/auth/me
// @access  Private
const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select('-password');
    if (req.securitySessionId) cloudSentinel.validateSession(req.securitySessionId).catch(() => {});
    res.json(user);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

const logout = async (req, res) => {
  try { await cloudSentinel.event(req.user, req, 'LOGOUT', { session_id: req.securitySessionId }); if (req.securitySessionId) await cloudSentinel.revokeSession(req.securitySessionId); } catch (_) {}
  res.json({ message:'Logged out successfully' });
};

const securityRequestStatus = async (req, res) => {
  try { const result = await cloudSentinel.accessStatus(req.params.requestId); return res.json(result.data); } catch (e) { return res.status(503).json({ message:'Security service unavailable' }); }
};

const completeSecurityRequest = async (req, res) => {
  try {
    const result = await cloudSentinel.accessStatus(req.params.requestId);
    if (result.data.status !== 'APPROVED') return res.status(409).json(result.data);
    const user = await User.findById(result.data.bookstream_user_id);
    if (!user) return res.status(404).json({message:'User not found'});
    if (user.status !== 'ACTIVE') return res.status(403).json({code:'ACCOUNT_RESTRICTED',message:'Your BookStream account is frozen, so you have been signed out. Please contact the BookStream administrator if you believe this is a mistake. Your account will remain blocked until an administrator reviews it.'});
    return res.json({_id:user._id,firstName:user.firstName,lastName:user.lastName,email:user.email,role:user.role,token:generateToken(user._id,result.data.security_session_id),security_session_id:result.data.security_session_id});
  } catch (e) { return res.status(503).json({ message:'Security service unavailable' }); }
};

module.exports = {
  register,
  logout,
  securityRequestStatus,
  completeSecurityRequest,
  login,
  getMe,
};
