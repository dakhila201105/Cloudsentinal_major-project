const crypto = require('crypto');
const axios = require('axios');

const baseURL = process.env.CLOUDSENTINEL_URL || 'http://127.0.0.1:8000';
const serviceKey = process.env.CLOUDSENTINEL_SERVICE_KEY || 'dev-integration-key';

const fingerprint = (req) => crypto.createHash('sha256').update(`${req.headers['user-agent'] || ''}|${req.headers['accept-language'] || ''}`).digest('hex').slice(0, 32);
const context = (req) => ({
  ip_address: req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || '127.0.0.1',
  user_agent: req.headers['user-agent'] || '',
  device_fingerprint: fingerprint(req),
});
const headers = () => ({ 'X-CloudSentinel-Service-Key': serviceKey });

async function registerUser(user) {
  return axios.post(`${baseURL}/api/integration/users`, {
    bookstream_user_id: String(user._id), username: user.firstName + ' ' + user.lastName, email: user.email, role: user.role, status: user.status || 'ACTIVE'
  }, { headers: headers(), timeout: 5000 });
}
async function evaluateLogin(user, req) {
  return axios.post(`${baseURL}/api/integration/login-evaluate`, { bookstream_user_id: String(user._id), ...context(req) }, { headers: headers(), timeout: 7000, validateStatus: s => s < 500 });
}
async function accessStatus(requestId) {
  return axios.post(`${baseURL}/api/integration/access-request/${requestId}/status`, {}, { headers: headers(), timeout: 5000 });
}
async function validateSession(securitySessionId) {
  return axios.post(`${baseURL}/api/integration/session/validate`, { security_session_id: securitySessionId }, { headers: headers(), timeout: 4000 });
}
async function revokeSession(securitySessionId) {
  return axios.post(`${baseURL}/api/integration/session/revoke`, { security_session_id: securitySessionId }, { headers: headers(), timeout: 4000 });
}
async function startSession(user, req) {
  const result = await axios.post(`${baseURL}/api/integration/session/start`, { bookstream_user_id: String(user._id), ...context(req) }, { headers: headers(), timeout: 5000 });
  return result.data.security_session_id;
}
async function event(user, req, eventType, data={}) {
  if (!user) return null;
  try {
    return await axios.post(`${baseURL}/api/integration/events`, {
      bookstream_user_id: String(user._id), event_type: eventType, ...context(req),
      session_id: data.session_id || req.securitySessionId, resource_id: data.resource_id, resource_name: data.resource_name, metadata: data.metadata || {}
    }, { headers: headers(), timeout: 4000 });
  } catch (e) {
    console.error('CloudSentinel event error:', e.response?.data || e.message);
    return null;
  }
}
module.exports = { registerUser, evaluateLogin, accessStatus, validateSession, revokeSession, startSession, event, context };
