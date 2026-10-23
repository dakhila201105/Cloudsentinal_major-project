import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FiBookmark, FiTrash2, FiBookOpen, FiUser, FiX } from 'react-icons/fi';
import { assetURL, bookmarksAPI } from '../services/api';

const BookmarksPage = () => {
  const [bookmarks, setBookmarks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [deleteModal, setDeleteModal] = useState({ show: false, bookmark: null });

  useEffect(() => {
    fetchBookmarks();
  }, []);

  const fetchBookmarks = async () => {
    try {
      setLoading(true);
      const response = await bookmarksAPI.getBookmarks();
      setBookmarks(response.data);
    } catch (error) {
      console.error('Error fetching bookmarks:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteBookmark = async (bookmarkId) => {
    try {
      await bookmarksAPI.deleteBookmark(bookmarkId);
      setBookmarks(bookmarks.filter(group =>
        group.bookmarks.some(b => b._id === bookmarkId)
          ? {
              ...group,
              bookmarks: group.bookmarks.filter(b => b._id !== bookmarkId)
            }
          : group
      ).filter(group => group.bookmarks.length > 0));
      setDeleteModal({ show: false, bookmark: null });
    } catch (error) {
      console.error('Error deleting bookmark:', error);
      alert('Failed to delete bookmark. Please try again.');
    }
  };

  const confirmDelete = (bookmark) => {
    setDeleteModal({ show: true, bookmark });
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center animate-fade-in">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">My Bookmarks</h1>
        <p className="text-lg text-gray-600 max-w-2xl mx-auto">
          Keep track of your favorite pages and easily jump back to them anytime
        </p>
      </div>

      {/* Bookmarks List */}
      {bookmarks.length === 0 ? (
        <div className="text-center py-16 animate-fade-in">
          <div className="text-gray-400 mb-4">
            <FiBookmark size={64} className="mx-auto" />
          </div>
          <h3 className="text-xl font-semibold text-gray-900 mb-2">
            No bookmarks yet
          </h3>
          <p className="text-gray-600 mb-6">
            Start reading books and bookmark pages you want to revisit later
          </p>
          <Link to="/books" className="btn-primary">
            Browse Books
          </Link>
        </div>
      ) : (
        <div className="grid gap-8">
          {bookmarks.map((group) => (
            <div key={group.book._id} className="card animate-slide-up">
              {/* Book Header */}
              <div className="flex items-start justify-between mb-6 pb-4 border-b border-gray-200">
                <Link
                  to={`/book/${group.book._id}`}
                  className="flex items-start space-x-4 flex-1 hover:opacity-80 transition duration-200"
                >
                  <img
                    src={assetURL(group.book.coverImage)}
                    alt={group.book.title}
                    className="w-16 h-24 object-cover rounded-lg shadow-md"
                    onError={(e) => {
                      e.target.src = 'https://via.placeholder.com/64x96/e5e7eb/6b7280?text=No+Cover';
                    }}
                  />
                  <div className="flex-1">
                    <h2 className="text-xl font-semibold text-gray-900 mb-1">
                      {group.book.title}
                    </h2>
                    <p className="text-gray-600 mb-2 flex items-center">
                      <FiUser className="mr-1" />
                      {group.book.author}
                    </p>
                    <p className="text-sm text-gray-500">
                      {group.bookmarks.length} bookmark{group.bookmarks.length !== 1 ? 's' : ''}
                    </p>
                  </div>
                </Link>
                <Link
                  to={`/book/${group.book._id}`}
                  className="btn-primary flex items-center"
                >
                  <FiBookOpen className="mr-2" />
                  Read Book
                </Link>
              </div>

              {/* Bookmarks Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {group.bookmarks.map((bookmark) => (
                  <div
                    key={bookmark._id}
                    className="flex items-center justify-between p-4 bg-gray-50 rounded-lg hover:bg-gray-100 transition duration-200"
                  >
                    <Link
                      to={`/book/${group.book._id}?page=${bookmark.pageNumber}`}
                      className="flex-1"
                    >
                      <div className="flex items-center space-x-2">
                        <FiBookmark className="text-purple-600" />
                        <span className="font-medium text-gray-900">
                          Page {bookmark.pageNumber}
                        </span>
                      </div>
                      <p className="text-sm text-gray-500 mt-1">
                        {new Date(bookmark.createdAt).toLocaleDateString()}
                      </p>
                    </Link>
                    <button
                      onClick={() => confirmDelete(bookmark)}
                      className="text-red-500 hover:text-red-700 p-1 transition duration-200"
                      title="Delete bookmark"
                    >
                      <FiTrash2 />
                    </button>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deleteModal.show && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Delete Bookmark</h3>
              <button
                onClick={() => setDeleteModal({ show: false, bookmark: null })}
                className="text-gray-400 hover:text-gray-600"
              >
                <FiX />
              </button>
            </div>

            <p className="text-gray-600 mb-6">
              Are you sure you want to delete this bookmark for page {deleteModal.bookmark?.pageNumber}?
              This action cannot be undone.
            </p>

            <div className="flex justify-end space-x-2">
              <button
                onClick={() => setDeleteModal({ show: false, bookmark: null })}
                className="btn-secondary"
              >
                Cancel
              </button>
              <button
                onClick={() => handleDeleteBookmark(deleteModal.bookmark._id)}
                className="btn-danger"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BookmarksPage;
