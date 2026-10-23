import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import Navbar from './components/Navbar';
import LandingPage from './pages/LandingPage';
import BooksPage from './pages/BooksPage';
import AuthPage from './pages/AuthPage';
import BookReaderPage from './pages/BookReaderPage';
import BookmarksPage from './pages/BookmarksPage';
import UploadBooksPage from './pages/UploadBooksPage';
import PrivateRoute from './components/PrivateRoute';
import './index.css';

function App() {
  return (
    <AuthProvider>
      <Router>
        <div className="min-h-screen bg-gray-50">
          <Navbar />
          <main className="container mx-auto px-4 py-8">
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route path="/books" element={<BooksPage />} />
              <Route path="/auth" element={<AuthPage />} />
              <Route path="/book/:id" element={<BookReaderPage />} />
              <Route
                path="/bookmarks"
                element={
                  <PrivateRoute>
                    <BookmarksPage />
                  </PrivateRoute>
                }
              />
              <Route
                path="/upload"
                element={
                  <PrivateRoute adminOnly>
                    <UploadBooksPage />
                  </PrivateRoute>
                }
              />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </main>
        </div>
      </Router>
    </AuthProvider>
  );
}

export default App;
