import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Document, Page, pdfjs } from 'react-pdf';
import {
  FiChevronLeft,
  FiChevronRight,
  FiBookmark,
  FiStar,
  FiDownload,
  FiUser,
  FiTag,
  FiInfo,
  FiZoomIn,
  FiZoomOut,
  FiRotateCcw,
  FiX
} from 'react-icons/fi';
import { assetURL, booksAPI, ratingsAPI, bookmarksAPI } from '../services/api';
import { useAuth } from '../context/AuthContext';

// Set up PDF.js worker
pdfjs.GlobalWorkerOptions.workerSrc = `//cdnjs.cloudflare.com/ajax/libs/pdf.js/${pdfjs.version}/pdf.worker.min.js`;

const BookReaderPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();

  const [book, setBook] = useState(null);
  const [loading, setLoading] = useState(true);
  const [numPages, setNumPages] = useState(null);
  const [pageNumber, setPageNumber] = useState(1);
  const [scale, setScale] = useState(1.0);
  const [rotation, setRotation] = useState(0);
  const [userRating, setUserRating] = useState(0);
  const [hoverRating, setHoverRating] = useState(0);
  const [showRatingModal, setShowRatingModal] = useState(false);
  const [bookmarks, setBookmarks] = useState([]);
  const [isBookmarked, setIsBookmarked] = useState(false);

useEffect(() => {
  fetchBookDetails();
  fetchUserRating();
  fetchBookmarks();
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [id]);

  const fetchBookDetails = async () => {
    try {
      setLoading(true);
      const response = await booksAPI.getBookById(id);
      setBook(response.data);
    } catch (error) {
      console.error('Error fetching book:', error);
      navigate('/books');
    } finally {
      setLoading(false);
    }
  };

  const fetchUserRating = async () => {
    if (!user) return;

    try {
      const response = await ratingsAPI.getUserRating(id);
      if (response.data.rating) {
        setUserRating(response.data.rating.rating);
      }
    } catch (error) {
      console.error('Error fetching user rating:', error);
    }
  };

  const fetchBookmarks = async () => {
    if (!user) return;

    try {
      const response = await bookmarksAPI.getBookmarksByBook(id);
      setBookmarks(response.data);
      setIsBookmarked(response.data.some(b => b.pageNumber === 1));
    } catch (error) {
      console.error('Error fetching bookmarks:', error);
    }
  };

  const onDocumentLoadSuccess = ({ numPages }) => {
    setNumPages(numPages);
  };

  const goToPrevPage = () => {
    setPageNumber(Math.max(1, pageNumber - 1));
  };

  const goToNextPage = () => {
    setPageNumber(Math.min(numPages, pageNumber + 1));
  };

  const handleRating = async (rating) => {
    try {
      await ratingsAPI.rateBook({ bookId: id, rating });
      setUserRating(rating);
      setShowRatingModal(false);
      // Refresh book data to update average rating
      fetchBookDetails();
    } catch (error) {
      console.error('Error rating book:', error);
      alert('Failed to submit rating. Please try again.');
    }
  };

  const handleBookmark = async () => {
    if (!user) {
      navigate('/auth');
      return;
    }

    try {
      if (isBookmarked) {
        await bookmarksAPI.deleteBookmarkByPage(id, pageNumber);
        setIsBookmarked(false);
        setBookmarks(bookmarks.filter(b => b.pageNumber !== pageNumber));
      } else {
        await bookmarksAPI.addBookmark({ bookId: id, pageNumber });
        setIsBookmarked(true);
        setBookmarks([...bookmarks, { pageNumber }]);
      }
    } catch (error) {
      console.error('Error managing bookmark:', error);
      alert('Failed to update bookmark. Please try again.');
    }
  };

  const handleDownload = async () => {
    try {
      const response = await booksAPI.downloadBook(id);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `${book.title}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error('Error downloading book:', error);
      alert('Failed to download book. Please try again.');
    }
  };

  const zoomIn = () => {
    setScale(Math.min(2.0, scale + 0.2));
  };

  const zoomOut = () => {
    setScale(Math.max(0.5, scale - 0.2));
  };

  const rotate = () => {
    setRotation((rotation + 90) % 360);
  };

  const renderStars = (rating, interactive = false, onRate = null) => {
    return (
      <div className="flex items-center space-x-1">
        {[1, 2, 3, 4, 5].map((star) => (
          <button
            key={star}
            onClick={() => interactive && onRate && onRate(star)}
            onMouseEnter={() => interactive && setHoverRating(star)}
            onMouseLeave={() => interactive && setHoverRating(0)}
            className={interactive ? 'cursor-pointer' : 'cursor-default'}
          >
            <FiStar
              className={`${
                star <= (hoverRating || rating)
                  ? 'text-yellow-400 fill-current'
                  : 'text-gray-300'
              } transition-colors duration-200`}
            />
          </button>
        ))}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="flex justify-center items-center min-h-screen">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!book) {
    return (
      <div className="text-center py-16">
        <h2 className="text-2xl font-bold text-gray-900 mb-4">Book not found</h2>
        <button
          onClick={() => navigate('/books')}
          className="btn-primary"
        >
          Back to Books
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-100">
      {/* Book Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="container mx-auto px-4 py-4">
          <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
            <div className="flex items-start space-x-4">
              <img
                src={assetURL(book.coverImage)}
                alt={book.title}
                className="w-20 h-28 object-cover rounded-lg shadow-md"
                onError={(e) => {
                  e.target.src = 'https://via.placeholder.com/80x112/e5e7eb/6b7280?text=No+Cover';
                }}
              />
              <div className="flex-1">
                <h1 className="text-2xl font-bold text-gray-900 mb-1">{book.title}</h1>
                <p className="text-lg text-gray-600 mb-2 flex items-center">
                  <FiUser className="mr-1" />
                  {book.author}
                </p>
                <div className="flex items-center space-x-4 text-sm text-gray-500">
                  <span className="flex items-center">
                    <FiTag className="mr-1" />
                    {book.genre}
                  </span>
                  <span className="flex items-center">
                    <FiInfo className="mr-1" />
                    {book.totalPages} pages
                  </span>
                </div>
                <div className="flex items-center mt-2">
                  {renderStars(book.averageRating)}
                  <span className="ml-2 text-sm text-gray-600">
                    ({book.totalRatings} ratings)
                  </span>
                </div>
              </div>
            </div>

            <div className="flex flex-col sm:flex-row gap-2">
              <button
                onClick={() => setShowRatingModal(true)}
                className="btn-secondary flex items-center justify-center"
              >
                <FiStar className="mr-2" />
                {userRating ? 'Update Rating' : 'Rate Book'}
              </button>
              <button
                onClick={handleDownload}
                className="btn-primary flex items-center justify-center"
              >
                <FiDownload className="mr-2" />
                Download PDF
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Reader */}
      <div className="container mx-auto px-4 py-8">
        <div className="grid lg:grid-cols-4 gap-8">
          {/* Sidebar */}
          <div className="lg:col-span-1 space-y-6">
            {/* Navigation Controls */}
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">Navigation</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <button
                    onClick={goToPrevPage}
                    disabled={pageNumber <= 1}
                    className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <FiChevronLeft />
                  </button>
                  <span className="text-sm font-medium">
                    Page {pageNumber} of {numPages}
                  </span>
                  <button
                    onClick={goToNextPage}
                    disabled={pageNumber >= numPages}
                    className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <FiChevronRight />
                  </button>
                </div>

                <button
                  onClick={handleBookmark}
                  className={`w-full btn-secondary flex items-center justify-center ${
                    isBookmarked ? 'bg-purple-100 text-purple-700' : ''
                  }`}
                >
                  <FiBookmark className={`mr-2 ${isBookmarked ? 'fill-current' : ''}`} />
                  {isBookmarked ? 'Bookmarked' : 'Bookmark Page'}
                </button>
              </div>
            </div>

            {/* Zoom Controls */}
            <div className="card">
              <h3 className="text-lg font-semibold mb-4">View Options</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <button onClick={zoomOut} className="btn-secondary">
                    <FiZoomOut />
                  </button>
                  <span className="text-sm font-medium">{Math.round(scale * 100)}%</span>
                  <button onClick={zoomIn} className="btn-secondary">
                    <FiZoomIn />
                  </button>
                </div>
                <button onClick={rotate} className="w-full btn-secondary flex items-center justify-center">
                  <FiRotateCcw className="mr-2" />
                  Rotate
                </button>
              </div>
            </div>

            {/* Bookmarks */}
            {bookmarks.length > 0 && (
              <div className="card">
                <h3 className="text-lg font-semibold mb-4">Bookmarks</h3>
                <div className="space-y-2">
                  {bookmarks.map((bookmark) => (
                    <button
                      key={bookmark._id}
                      onClick={() => setPageNumber(bookmark.pageNumber)}
                      className={`w-full text-left px-3 py-2 rounded-lg transition duration-200 ${
                        bookmark.pageNumber === pageNumber
                          ? 'bg-purple-100 text-purple-700'
                          : 'hover:bg-gray-100'
                      }`}
                    >
                      Page {bookmark.pageNumber}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* PDF Viewer */}
          <div className="lg:col-span-3">
            <div className="bg-white rounded-lg shadow-lg p-4">
              <div className="flex justify-center">
                <Document
                  file={assetURL(book.pdfFile)}
                  onLoadSuccess={onDocumentLoadSuccess}
                  loading={
                    <div className="flex justify-center items-center h-96">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                    </div>
                  }
                  error={
                    <div className="text-center py-16">
                      <p className="text-red-600 mb-4">Failed to load PDF</p>
                      <button onClick={handleDownload} className="btn-primary">
                        Download Instead
                      </button>
                    </div>
                  }
                >
                  <Page
                    pageNumber={pageNumber}
                    scale={scale}
                    rotate={rotation}
                    loading={
                      <div className="flex justify-center items-center h-64">
                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
                      </div>
                    }
                  />
                </Document>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Rating Modal */}
      {showRatingModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg p-6 max-w-md w-full mx-4">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Rate this book</h3>
              <button
                onClick={() => setShowRatingModal(false)}
                className="text-gray-400 hover:text-gray-600"
              >
                <FiX />
              </button>
            </div>

            <div className="mb-6">
              {renderStars(userRating, true, handleRating)}
              <p className="text-sm text-gray-600 mt-2">
                {userRating ? `You rated this book ${userRating} star${userRating !== 1 ? 's' : ''}` : 'Click to rate'}
              </p>
            </div>

            <div className="flex justify-end space-x-2">
              <button
                onClick={() => setShowRatingModal(false)}
                className="btn-secondary"
              >
                Cancel
              </button>
              {userRating > 0 && (
                <button
                  onClick={() => handleRating(0)}
                  className="btn-danger"
                >
                  Remove Rating
                </button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BookReaderPage;
