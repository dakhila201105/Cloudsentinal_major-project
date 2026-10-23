import React from 'react';
import { Link } from 'react-router-dom';
import { FiBookOpen, FiDownload, FiBookmark, FiStar } from 'react-icons/fi';

const LandingPage = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 via-white to-teal-50">
      {/* Hero Section */}
      <div className="container mx-auto px-4 py-16">
        <div className="text-center animate-fade-in">
          <h1 className="text-5xl md:text-6xl font-bold text-gray-900 mb-6">
            Welcome to{' '}
            <span className="text-blue-600">BookStream</span>
          </h1>
          <p className="text-xl md:text-2xl text-gray-600 mb-8 max-w-3xl mx-auto">
            Your ultimate destination for free ebooks. Read, download, and bookmark your favorite books online.
          </p>
          <Link
            to="/books"
            className="inline-block bg-blue-600 hover:bg-blue-700 text-white text-lg font-semibold py-4 px-8 rounded-full transition duration-300 transform hover:scale-105 animate-bounce-in"
          >
            Enter BookStream
          </Link>
        </div>

        {/* Features Section */}
        <div className="mt-20 grid md:grid-cols-2 lg:grid-cols-4 gap-8">
          <div className="card text-center animate-slide-up">
            <div className="w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <FiBookOpen className="text-2xl text-blue-600" />
            </div>
            <h3 className="text-xl font-semibold mb-2">Read Online</h3>
            <p className="text-gray-600">
              Enjoy seamless reading experience with our interactive book reader
            </p>
          </div>

          <div className="card text-center animate-slide-up" style={{ animationDelay: '0.1s' }}>
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <FiDownload className="text-2xl text-green-600" />
            </div>
            <h3 className="text-xl font-semibold mb-2">Download Books</h3>
            <p className="text-gray-600">
              Download your favorite books in PDF format for offline reading
            </p>
          </div>

          <div className="card text-center animate-slide-up" style={{ animationDelay: '0.2s' }}>
            <div className="w-16 h-16 bg-purple-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <FiBookmark className="text-2xl text-purple-600" />
            </div>
            <h3 className="text-xl font-semibold mb-2">Bookmark Pages</h3>
            <p className="text-gray-600">
              Save your favorite pages and easily navigate back to them anytime
            </p>
          </div>

          <div className="card text-center animate-slide-up" style={{ animationDelay: '0.3s' }}>
            <div className="w-16 h-16 bg-yellow-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <FiStar className="text-2xl text-yellow-600" />
            </div>
            <h3 className="text-xl font-semibold mb-2">Rate Books</h3>
            <p className="text-gray-600">
              Share your thoughts by rating books and help others discover great reads
            </p>
          </div>
        </div>

        {/* Call to Action */}
        <div className="mt-20 text-center animate-fade-in" style={{ animationDelay: '0.5s' }}>
          <div className="bg-white rounded-2xl shadow-xl p-8 max-w-4xl mx-auto">
            <h2 className="text-3xl font-bold text-gray-900 mb-4">
              Start Your Reading Journey Today
            </h2>
            <p className="text-lg text-gray-600 mb-6">
              Join thousands of readers who have discovered their next favorite book on BookStream.
              Browse our extensive collection and start reading instantly.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link
                to="/books"
                className="btn-primary text-lg px-8 py-3"
              >
                Browse Books
              </Link>
              <Link
                to="/auth"
                className="btn-secondary text-lg px-8 py-3"
              >
                Create Account
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default LandingPage;
