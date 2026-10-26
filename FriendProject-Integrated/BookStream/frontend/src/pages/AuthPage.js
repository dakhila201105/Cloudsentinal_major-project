import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { FiMail, FiLock, FiUser, FiEye, FiEyeOff } from 'react-icons/fi';
import { authAPI } from '../services/api';

const AuthPage = () => {
  const restrictedNotice = new URLSearchParams(window.location.search).get('restricted') === '1'
    ? (sessionStorage.getItem('bookstreamAuthNotice') || 'Your BookStream account is frozen, so you have been signed out. Please contact the BookStream administrator if you believe this is a mistake. Your account will remain blocked until an administrator reviews it.')
    : '';
  const [isSignUp, setIsSignUp] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
  });
  const [errors, setErrors] = useState({});
  const [dualApproval, setDualApproval] = useState(null);
  const [emailOtp, setEmailOtp] = useState('');
  const [otpMessage, setOtpMessage] = useState('');
  const [otpLoading, setOtpLoading] = useState(false);
  const [clock, setClock] = useState(Date.now());
  const pollTimer = useRef(null);

  const { login, register } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const from = location.state?.from?.pathname || '/books';

  useEffect(() => {
    if (dualApproval?.step !== 'USER_OTP') return undefined;
    const timer = window.setInterval(() => setClock(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [dualApproval?.step]);

  useEffect(() => () => window.clearTimeout(pollTimer.current), []);

  const waitForAdmin = (requestId) => {
    const started = Date.now();
    const poll = async () => {
      try {
        const response = await authAPI.securityRequestStatus(requestId);
        if (response.data.status === 'APPROVED' && response.data.security_session_id) {
          const completed = await authAPI.completeSecurityRequest(requestId);
          const { token, ...userData } = completed.data;
          localStorage.setItem('token', token);
          localStorage.setItem('user', JSON.stringify(userData));
          window.location.href = from;
          return;
        }
        if (response.data.status === 'DENIED') {
          setOtpMessage(response.data.message || 'The administrator denied this sign-in. Contact the BookStream administrator if you think this is a mistake.');
          setDualApproval((current) => current ? { ...current, step: 'DONE' } : current);
          return;
        }
        if (Date.now() - started < 15 * 60 * 1000) {
          pollTimer.current = window.setTimeout(poll, 2500);
        } else {
          setOtpMessage('This administrator review timed out. Please sign in again.');
          setDualApproval((current) => current ? { ...current, step: 'DONE' } : current);
        }
      } catch (error) {
        if (Date.now() - started < 15 * 60 * 1000) pollTimer.current = window.setTimeout(poll, 4000);
        else {
          setOtpMessage('We could not confirm the administrator decision. Please sign in again.');
          setDualApproval((current) => current ? { ...current, step: 'DONE' } : current);
        }
      }
    };
    pollTimer.current = window.setTimeout(poll, 1500);
  };

  const verifyEmailOtp = async (event) => {
    event.preventDefault();
    setOtpLoading(true);
    setOtpMessage('');
    try {
      const response = await authAPI.verifyLoginOtp(dualApproval.requestId, emailOtp);
      if (response.data?.status === 'PENDING' && response.data?.step === 'ADMIN_APPROVAL') {
        setDualApproval((current) => ({ ...current, step: 'ADMIN_PENDING' }));
        setEmailOtp('');
        setOtpMessage('Email verified. Your request is now waiting for CloudSentinel administrator approval.');
        waitForAdmin(dualApproval.requestId);
      } else {
        setOtpMessage(response.data?.message || 'Email verification did not complete.');
      }
    } catch (error) {
      setOtpMessage(error.response?.data?.message || 'Could not verify that code. Please try again.');
      if (error.response?.data?.status === 'DENIED') setDualApproval((current) => ({ ...current, step: 'DONE' }));
    } finally {
      setOtpLoading(false);
    }
  };

  const resendEmailOtp = async () => {
    setOtpLoading(true);
    setOtpMessage('');
    try {
      const response = await authAPI.resendLoginOtp(dualApproval.requestId);
      const delay = Number(response.data?.resend_after_seconds || 120);
      setDualApproval((current) => ({ ...current, resendAt: Date.now() + delay * 1000 }));
      setEmailOtp('');
      setOtpMessage(response.data?.message || 'A new code was sent to your registered email.');
    } catch (error) {
      setOtpMessage(error.response?.data?.message || 'Could not send another code.');
    } finally {
      setOtpLoading(false);
    }
  };

  const restartSignIn = () => {
    window.clearTimeout(pollTimer.current);
    setDualApproval(null);
    setEmailOtp('');
    setOtpMessage('');
    setErrors({});
    setFormData((current) => ({ ...current, password: '' }));
  };

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
    // Clear error when user starts typing
    if (errors[e.target.name]) {
      setErrors({
        ...errors,
        [e.target.name]: '',
      });
    }
  };

  const validateForm = () => {
    const newErrors = {};

    if (isSignUp) {
      if (!formData.firstName.trim()) {
        newErrors.firstName = 'First name is required';
      }
      if (!formData.lastName.trim()) {
        newErrors.lastName = 'Last name is required';
      }
    }

    if (!formData.email.trim()) {
      newErrors.email = 'Email is required';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'Email is invalid';
    }

    if (!formData.password) {
      newErrors.password = 'Password is required';
    } else if (formData.password.length < 6) {
      newErrors.password = 'Password must be at least 6 characters';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setLoading(true);

    try {
      let result;
      if (isSignUp) {
        result = await register(formData);
        if (result.success) {
          // Show success message and switch to sign in
          alert('Registered successfully! Please sign in.');
          setIsSignUp(false);
          setFormData({
            firstName: '',
            lastName: '',
            email: formData.email,
            password: '',
          });
        } else {
          setErrors({ submit: result.message });
        }
      } else {
        result = await login(formData.email, formData.password);
        if (result.success) {
          navigate(from, { replace: true });
        } else if (result.verificationRequired) {
          setErrors({});
          setEmailOtp('');
          setOtpMessage('');
          setDualApproval({ step: 'USER_OTP', requestId: result.requestId, email: result.email,
            resendAt: Date.now() + Number(result.resendAfterSeconds || 120) * 1000 });
        } else if (result.pending) {
          setErrors({ submit: 'Your BookStream account is frozen. This sign-in attempt has been sent to the administrator for review. Please contact the BookStream administrator if you believe this is a mistake. Repeated sign-in attempts increase the account risk score.' });
          const started = Date.now();
          const poll = async () => {
            try {
              const r = await authAPI.securityRequestStatus(result.requestId);
              if (r.data.status === 'APPROVED' && r.data.security_session_id) {
                const userResult = await authAPI.completeSecurityRequest(result.requestId);
                const { token, ...userData } = userResult.data;
                localStorage.setItem('token', token); localStorage.setItem('user', JSON.stringify(userData));
                window.location.href = from; return;
              }
              if (r.data.status === 'DENIED') { setErrors({ submit:r.data.message || 'Administrator denied the login request.' }); return; }
              if (Date.now() - started < 120000) setTimeout(poll, 3000);
              else setErrors({ submit:'Approval request expired. Please try again.' });
            } catch (_) { if (Date.now() - started < 120000) setTimeout(poll, 3000); }
          };
          setTimeout(poll, 3000);
        } else {
          setErrors({ submit: result.message });
        }
      }
    } catch (error) {
      setErrors({ submit: 'An error occurred. Please try again.' });
    } finally {
      setLoading(false);
    }
  };

  const toggleMode = () => {
    setIsSignUp(!isSignUp);
    setErrors({});
    setFormData({
      firstName: '',
      lastName: '',
      email: '',
      password: '',
    });
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-teal-50 py-12 px-4">
      <div className="max-w-md w-full space-y-8">
        <div className="card animate-fade-in">
          <div className="text-center mb-8">
            <h2 className="text-3xl font-bold text-gray-900">
              {dualApproval ? (dualApproval.step === 'USER_OTP' ? 'Verify your email' : dualApproval.step === 'ADMIN_PENDING' ? 'Waiting for administrator approval' : 'Sign-in request complete') : (isSignUp ? 'Create Account' : 'Sign In')}
            </h2>
            <p className="text-gray-600 mt-2">
              {dualApproval?.step === 'USER_OTP'
                ? `Enter the six-digit code sent to ${dualApproval.email}.`
                : dualApproval?.step === 'ADMIN_PENDING'
                  ? 'Your email is verified. CloudSentinel is waiting for an administrator to review this device and approve access.'
                  : dualApproval?.step === 'DONE'
                    ? 'This sign-in could not be approved.'
                    : isSignUp
                ? 'Join BookStream and start your reading journey'
                : 'Welcome back! Please sign in to your account'
              }
            </p>
          </div>

          {restrictedNotice && <div role="alert" className="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg mb-4">{restrictedNotice}</div>}
          {!dualApproval ? (
          <form onSubmit={handleSubmit} className="space-y-6">
            {isSignUp && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label htmlFor="firstName" className="block text-sm font-medium text-gray-700 mb-1">
                    First Name
                  </label>
                  <div className="relative">
                    <FiUser className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                    <input
                      id="firstName"
                      name="firstName"
                      type="text"
                      value={formData.firstName}
                      onChange={handleChange}
                      className={`input-field pl-10 ${errors.firstName ? 'border-red-500 focus:ring-red-500' : ''}`}
                      placeholder="John"
                    />
                  </div>
                  {errors.firstName && (
                    <p className="text-red-500 text-xs mt-1">{errors.firstName}</p>
                  )}
                </div>

                <div>
                  <label htmlFor="lastName" className="block text-sm font-medium text-gray-700 mb-1">
                    Last Name
                  </label>
                  <div className="relative">
                    <FiUser className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                    <input
                      id="lastName"
                      name="lastName"
                      type="text"
                      value={formData.lastName}
                      onChange={handleChange}
                      className={`input-field pl-10 ${errors.lastName ? 'border-red-500 focus:ring-red-500' : ''}`}
                      placeholder="Doe"
                    />
                  </div>
                  {errors.lastName && (
                    <p className="text-red-500 text-xs mt-1">{errors.lastName}</p>
                  )}
                </div>
              </div>
            )}

            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-1">
                Email Address
              </label>
              <div className="relative">
                <FiMail className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <input
                  id="email"
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleChange}
                  className={`input-field pl-10 ${errors.email ? 'border-red-500 focus:ring-red-500' : ''}`}
                  placeholder="john@example.com"
                />
              </div>
              {errors.email && (
                <p className="text-red-500 text-xs mt-1">{errors.email}</p>
              )}
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-1">
                Password
              </label>
              <div className="relative">
                <FiLock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  value={formData.password}
                  onChange={handleChange}
                  className={`input-field pl-10 pr-10 ${errors.password ? 'border-red-500 focus:ring-red-500' : ''}`}
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <FiEyeOff /> : <FiEye />}
                </button>
              </div>
              {errors.password && (
                <p className="text-red-500 text-xs mt-1">{errors.password}</p>
              )}
            </div>

            {errors.submit && (
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
                {errors.submit}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed py-3"
            >
              {loading ? (
                <div className="flex items-center justify-center">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                  {isSignUp ? 'Creating Account...' : 'Signing In...'}
                </div>
              ) : (
                isSignUp ? 'Create Account' : 'Sign In'
              )}
            </button>
          </form>
          ) : (
            <div className="space-y-5">
              {dualApproval.step === 'USER_OTP' && (
                <form onSubmit={verifyEmailOtp} className="space-y-4">
                  <div>
                    <label htmlFor="emailOtp" className="block text-sm font-medium text-gray-700 mb-1">Email verification code</label>
                    <input id="emailOtp" name="emailOtp" type="text" inputMode="numeric" autoComplete="one-time-code" maxLength={6}
                      value={emailOtp} onChange={(event) => setEmailOtp(event.target.value.replace(/\D/g, '').slice(0, 6))}
                      className="input-field text-center tracking-[0.4em] text-lg" placeholder="000000" required />
                    <p className="text-xs text-gray-500 mt-2">The code expires in two minutes. If it expires, you can request a new one after the timer.</p>
                  </div>
                  {otpMessage && <div role="status" className="bg-blue-50 border border-blue-200 text-blue-800 px-4 py-3 rounded-lg">{otpMessage}</div>}
                  <button type="submit" disabled={otpLoading || emailOtp.length !== 6} className="w-full btn-primary disabled:opacity-50 py-3">
                    {otpLoading ? 'Verifying…' : 'Verify email and continue'}
                  </button>
                  {Math.max(0, Math.ceil((dualApproval.resendAt - clock) / 1000)) > 0 ? (
                    <p className="text-center text-sm text-gray-500">Request another code in {Math.max(0, Math.ceil((dualApproval.resendAt - clock) / 1000))} seconds</p>
                  ) : (
                    <button type="button" onClick={resendEmailOtp} disabled={otpLoading} className="w-full text-blue-600 hover:text-blue-700 font-medium disabled:opacity-50">
                      {otpLoading ? 'Sending…' : 'Request a new code'}
                    </button>
                  )}
                </form>
              )}
              {dualApproval.step === 'ADMIN_PENDING' && (
                <div className="text-center py-5">
                  <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600 mx-auto mb-4"></div>
                  <p className="font-medium text-gray-800">Waiting for CloudSentinel</p>
                  <p className="text-sm text-gray-600 mt-2">The administrator received your device ID and a request-specific approval code. You’ll be signed in here after approval.</p>
                  {otpMessage && <div role="status" className="bg-blue-50 border border-blue-200 text-blue-800 px-4 py-3 rounded-lg mt-4">{otpMessage}</div>}
                </div>
              )}
              {dualApproval.step === 'DONE' && otpMessage && <div role="alert" className="bg-red-50 border border-red-200 text-red-800 px-4 py-3 rounded-lg">{otpMessage}</div>}
              {(dualApproval.step === 'USER_OTP' || dualApproval.step === 'DONE') && (
                <button type="button" onClick={restartSignIn} className="w-full text-sm text-gray-600 hover:text-gray-900">Back to sign in</button>
              )}
            </div>
          )}

          {!dualApproval && <div className="mt-6 text-center">
            <button
              onClick={toggleMode}
              className="text-blue-600 hover:text-blue-700 font-medium transition duration-200"
            >
              {isSignUp
                ? 'Already have an account? Sign In'
                : "Don't have an account? Create Account"
              }
            </button>
          </div>}

          {!dualApproval && !isSignUp && (
            <div className="mt-4 p-4 bg-blue-50 rounded-lg">
              <p className="text-sm text-blue-800">
                <strong>Admin Access:</strong> To create an admin account, register with an email ending in @admin.com
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AuthPage;
