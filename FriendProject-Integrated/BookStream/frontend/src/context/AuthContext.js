import React, { createContext, useState, useContext, useEffect } from 'react';
import { authAPI } from '../services/api';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check if user is logged in on app start
    const token = localStorage.getItem('token');
    const userData = localStorage.getItem('user');

    if (token && userData) {
      setUser(JSON.parse(userData));
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    if (!user) return undefined;
    const checkAccount = async () => {
      try { await authAPI.getMe(); }
      catch (error) {
        if (error.response?.status === 403 && error.response?.data?.code === 'ACCOUNT_RESTRICTED') {
          localStorage.removeItem('token'); localStorage.removeItem('user');
          sessionStorage.setItem('bookstreamAuthNotice', 'Your BookStream account is frozen, so you have been signed out. Please contact the BookStream administrator if you believe this is a mistake. Your account will remain blocked until an administrator reviews it.');
          setUser(null); window.location.href = '/auth?restricted=1';
        }
      }
    };
    checkAccount();
    const timer = window.setInterval(checkAccount, 5000);
    return () => window.clearInterval(timer);
  }, [user]);

  const login = async (email, password) => {
    try {
      const response = await authAPI.login({ email, password });
      if (response.data?.step === 'USER_OTP_REQUIRED' && response.data?.request_id) {
        return {
          success: false,
          verificationRequired: true,
          requestId: response.data.request_id,
          email: response.data.email,
          resendAfterSeconds: response.data.resend_after_seconds,
          otpValidSeconds: response.data.otp_valid_seconds,
        };
      }
      if (response.status === 202 && response.data?.request_id) {
        return { success: false, pending: true, requestId: response.data.request_id, message: response.data.message || 'Administrator approval required' };
      }
      const { token, ...userData } = response.data;

      localStorage.setItem('token', token);
      localStorage.setItem('user', JSON.stringify(userData));
      setUser(userData);

      return { success: true };
    } catch (error) {
      if (error.response?.status === 202 && error.response?.data?.request_id) {
        return { success:false, pending:true, requestId:error.response.data.request_id, message:'Administrator approval required' };
      }
      return { success: false, message: error.response?.data?.message || 'Login failed' };
    }
  };

  const register = async (userData) => {
    try {
      const response = await authAPI.register(userData);
      return { success: true, message: response.data.message };
    } catch (error) {
      return {
        success: false,
        message: error.response?.data?.message || 'Registration failed'
      };
    }
  };

  const logout = async () => {
    try { if (localStorage.getItem('token')) await authAPI.logout(); } catch (_) {}
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    sessionStorage.removeItem('bookstreamAuthNotice');
    setUser(null);
  };

  const updateUser = (userData) => {
    setUser(userData);
    localStorage.setItem('user', JSON.stringify(userData));
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout,
    updateUser,
    isAuthenticated: !!user,
    isAdmin: user?.role === 'admin',
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
