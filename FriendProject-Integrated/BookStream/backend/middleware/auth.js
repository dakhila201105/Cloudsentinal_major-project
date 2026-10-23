const jwt = require('jsonwebtoken');
const User = require('../models/User');

const protect = async (req, res, next) => {
  if (!(req.headers.authorization && req.headers.authorization.startsWith('Bearer'))) return res.status(401).json({ message: 'Not authorized, no token' });
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    if (!req.user) return res.status(401).json({ message: 'Not authorized, user not found' });
    if (req.user.status !== 'ACTIVE') return res.status(403).json({ code: 'ACCOUNT_RESTRICTED', message: 'Your BookStream account is frozen, so you have been signed out. Please contact the BookStream administrator if you believe this is a mistake. Your account will remain blocked until an administrator reviews it.' });
    // BookStream JWTs are validated against the local user database. Older
    // tokens may still carry a CloudSentinel session id for optional auditing.
    req.securitySessionId = decoded.security_session_id;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Not authorized, token failed' });
  }
};

const admin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') next();
  else res.status(403).json({ message: 'Not authorized as admin' });
};
module.exports = { protect, admin };

const optionalProtect = async (req, res, next) => {
  try {
    const h=req.headers.authorization||''; if(!h.startsWith('Bearer ')) return next();
    const decoded=jwt.verify(h.split(' ')[1], process.env.JWT_SECRET);
    const user=await User.findById(decoded.id).select('-password'); if(!user) return next();
    req.user=user; req.securitySessionId=decoded.security_session_id;
  } catch (_) {}
  next();
};
module.exports.optionalProtect = optionalProtect;
