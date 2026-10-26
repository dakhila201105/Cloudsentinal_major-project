import axios from 'axios';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:5001/api';
const ASSET_BASE_URL = API_URL.replace(/\/api\/?$/, '').replace(/\/+$/, '');
const DEVICE_ID_KEY = 'bookstreamDeviceId';

const getBookStreamDeviceId = () => {
  let deviceId = localStorage.getItem(DEVICE_ID_KEY);
  if (!deviceId) {
    deviceId = window.crypto?.randomUUID
      ? window.crypto.randomUUID()
      : `bs-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}${Math.random().toString(36).slice(2)}`;
    localStorage.setItem(DEVICE_ID_KEY, deviceId);
  }
  return deviceId;
};

export const assetURL = (filePath) => {
  if (!filePath) return '';
  const normalizedPath = filePath.replace(/\\/g, '/').replace(/^\/+/, '');
  return `${ASSET_BASE_URL}/${normalizedPath}`;
};

// Create axios instance
const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    config.headers['X-BookStream-Device-ID'] = getBookStreamDeviceId();
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle token expiration
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/auth';
    }
    if (error.response?.status === 403 && error.response?.data?.code === 'ACCOUNT_RESTRICTED' && !error.config?.url?.includes('/auth/login')) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      sessionStorage.setItem('bookstreamAuthNotice', 'Your BookStream account is frozen, so you have been signed out. Please contact the BookStream administrator if you believe this is a mistake. Your account will remain blocked until an administrator reviews it.');
      window.location.href = '/auth?restricted=1';
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authAPI = {
  register: (userData) => api.post('/auth/register', userData),
  login: (userData) => api.post('/auth/login', userData),
  verifyLoginOtp: (requestId, code) => api.post(`/auth/dual-approval/${encodeURIComponent(requestId)}/verify-user`, { code }),
  resendLoginOtp: (requestId) => api.post(`/auth/dual-approval/${encodeURIComponent(requestId)}/resend-user`),
  getMe: () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout'),
  securityRequestStatus: (requestId) => api.get(`/auth/security-request/${requestId}`),
  completeSecurityRequest: (requestId) => api.post(`/auth/security-request/${requestId}/complete`),
};

// Books API
export const booksAPI = {
  getBooks: (params) => api.get('/books', { params }),
  getBookById: (id) => api.get(`/books/${id}`),
  downloadBook: (id) => api.get(`/books/${id}/download`, { responseType: 'blob' }),
  uploadBook: (formData) => api.post('/books', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  }),
  deleteBook: (id) => api.delete(`/books/${id}`),
};

// Ratings API
export const ratingsAPI = {
  rateBook: (data) => api.post('/ratings', data),
  getUserRating: (bookId) => api.get(`/ratings/${bookId}`),
  deleteRating: (bookId) => api.delete(`/ratings/${bookId}`),
};

// Bookmarks API
export const bookmarksAPI = {
  addBookmark: (data) => api.post('/bookmarks', data),
  getBookmarks: () => api.get('/bookmarks'),
  getBookmarksByBook: (bookId) => api.get(`/bookmarks/${bookId}`),
  deleteBookmark: (id) => api.delete(`/bookmarks/${id}`),
  deleteBookmarkByPage: (bookId, pageNumber) => api.delete(`/bookmarks/${bookId}/${pageNumber}`),
};

export default api;
