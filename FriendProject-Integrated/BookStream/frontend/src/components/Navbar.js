import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { FiHome, FiBookmark, FiUpload, FiUser, FiLogOut, FiMenu, FiX } from 'react-icons/fi';

const Navbar = () => {
  const { user, isAuthenticated, isAdmin, logout } = useAuth();
  const navigate = useNavigate();
  const [isOpen, setIsOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/');
    setIsOpen(false);
  };

  const toggleMenu = () => {
    setIsOpen(!isOpen);
  };

  const closeMenu = () => {
    setIsOpen(false);
  };

  return (
    <nav className="navbar">
      <div className="container mx-auto px-4">
        <div className="flex justify-between items-center h-16">
          {/* Logo */}
          <Link to="/" className="text-xl font-bold text-blue-600 hover:text-blue-700 transition duration-200">
            BookStream
          </Link>

          {/* Desktop Navigation */}
          <div className="hidden md:flex items-center space-x-8">
            <Link to="/" className="navbar-link">
              <FiHome className="inline mr-1" />
              Home
            </Link>

            <Link to="/books" className="navbar-link">
              Books
            </Link>

            {isAuthenticated ? (
              <>
                <Link to="/bookmarks" className="navbar-link">
                  <FiBookmark className="inline mr-1" />
                  Bookmarks
                </Link>

                {isAdmin && (
                  <Link to="/upload" className="navbar-link">
                    <FiUpload className="inline mr-1" />
                    Upload
                  </Link>
                )}

                <div className="flex items-center space-x-2">
                  <FiUser className="text-gray-600" />
                  <span className="text-gray-700 font-medium">
                    {user?.firstName} {user?.lastName}
                  </span>
                  <button
                    onClick={handleLogout}
                    className="navbar-link text-red-600 hover:text-red-700"
                  >
                    <FiLogOut className="inline mr-1" />
                    Logout
                  </button>
                </div>
              </>
            ) : (
              <Link to="/auth" className="btn-primary">
                Sign In
              </Link>
            )}
          </div>

          {/* Mobile menu button */}
          <div className="md:hidden">
            <button
              onClick={toggleMenu}
              className="text-gray-700 hover:text-blue-600 transition duration-200"
            >
              {isOpen ? <FiX size={24} /> : <FiMenu size={24} />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {isOpen && (
          <div className="md:hidden py-4 border-t border-gray-200 animate-slide-up">
            <div className="flex flex-col space-y-4">
              <Link
                to="/"
                className="navbar-link"
                onClick={closeMenu}
              >
                <FiHome className="inline mr-2" />
                Home
              </Link>

              <Link
                to="/books"
                className="navbar-link"
                onClick={closeMenu}
              >
                Books
              </Link>

              {isAuthenticated ? (
                <>
                  <Link
                    to="/bookmarks"
                    className="navbar-link"
                    onClick={closeMenu}
                  >
                    <FiBookmark className="inline mr-2" />
                    Bookmarks
                  </Link>

                  {isAdmin && (
                    <Link
                      to="/upload"
                      className="navbar-link"
                      onClick={closeMenu}
                    >
                      <FiUpload className="inline mr-2" />
                      Upload
                    </Link>
                  )}

                  <div className="flex items-center justify-between pt-2 border-t border-gray-200">
                    <div className="flex items-center space-x-2">
                      <FiUser className="text-gray-600" />
                      <span className="text-gray-700 font-medium">
                        {user?.firstName} {user?.lastName}
                      </span>
                    </div>
                    <button
                      onClick={handleLogout}
                      className="navbar-link text-red-600 hover:text-red-700"
                    >
                      <FiLogOut className="inline mr-1" />
                      Logout
                    </button>
                  </div>
                </>
              ) : (
                <Link
                  to="/auth"
                  className="btn-primary text-center"
                  onClick={closeMenu}
                >
                  Sign In
                </Link>
              )}
            </div>
          </div>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
