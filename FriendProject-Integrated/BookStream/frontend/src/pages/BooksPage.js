import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { FiSearch, FiStar, FiUser, FiChevronLeft, FiChevronRight } from 'react-icons/fi';
import { assetURL, booksAPI } from '../services/api';

const BooksPage = () => {
  const [books, setBooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalBooks, setTotalBooks] = useState(0);

useEffect(() => {
  fetchBooks();
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [currentPage, searchTerm]);

  const fetchBooks = async () => {
    try {
      setLoading(true);
      const params = {
        page: currentPage,
        limit: 12,
        search: searchTerm,
      };

      const response = await booksAPI.getBooks(params);
      setBooks(response.data.books);
      setTotalPages(response.data.totalPages);
      setTotalBooks(response.data.totalBooks);
    } catch (error) {
      console.error('Error fetching books:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    setCurrentPage(1);
    fetchBooks();
  };

  const handlePageChange = (page) => {
    setCurrentPage(page);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const renderStars = (rating) => {
    const stars = [];
    const fullStars = Math.floor(rating);
    const hasHalfStar = rating % 1 !== 0;

    for (let i = 0; i < fullStars; i++) {
      stars.push(
        <FiStar key={i} className="text-yellow-400 fill-current" />
      );
    }

    if (hasHalfStar) {
      stars.push(
        <FiStar key="half" className="text-yellow-400 fill-current opacity-50" />
      );
    }

    const emptyStars = 5 - Math.ceil(rating);
    for (let i = 0; i < emptyStars; i++) {
      stars.push(
        <FiStar key={`empty-${i}`} className="text-gray-300" />
      );
    }

    return stars;
  };

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center animate-fade-in">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">Browse Books</h1>
        <p className="text-lg text-gray-600 max-w-2xl mx-auto">
          Discover your next favorite book from our extensive collection of free ebooks
        </p>
      </div>

      {/* Search Bar */}
      <div className="max-w-md mx-auto animate-slide-up">
        <form onSubmit={handleSearch} className="relative">
          <FiSearch className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" />
          <input
            type="text"
            placeholder="Search by title or author..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="input-field pl-10 pr-4"
          />
        </form>
      </div>

      {/* Results Count */}
      {!loading && (
        <div className="text-center text-gray-600">
          {searchTerm ? (
            <p>
              Found {totalBooks} book{totalBooks !== 1 ? 's' : ''} for "{searchTerm}"
            </p>
          ) : (
            <p>Showing {totalBooks} total books</p>
          )}
        </div>
      )}

      {/* Loading State */}
      {loading ? (
        <div className="flex justify-center items-center py-16">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
        </div>
      ) : (
        <>
          {/* Books Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {books.map((book) => (
              <Link
                key={book._id}
                to={`/book/${book._id}`}
                className="card hover:shadow-lg transition duration-300 transform hover:-translate-y-1 animate-fade-in"
              >
                <div className="aspect-[3/4] mb-4 overflow-hidden rounded-lg">
                  <img
                    src={assetURL(book.coverImage)}
                    alt={book.title}
                    className="w-full h-full object-cover"
                    onError={(e) => {
                      e.target.src = 'https://via.placeholder.com/300x400/e5e7eb/6b7280?text=No+Cover';
                    }}
                  />
                </div>

                <div className="space-y-2">
                  <h3 className="font-semibold text-lg text-gray-900 line-clamp-2">
                    {book.title}
                  </h3>

                  <p className="text-gray-600 text-sm flex items-center">
                    <FiUser className="mr-1" />
                    {book.author}
                  </p>

                  <div className="flex items-center justify-between">
                    <div className="flex items-center">
                      {renderStars(book.averageRating)}
                      <span className="ml-2 text-sm text-gray-600">
                        ({book.totalRatings})
                      </span>
                    </div>
                  </div>

                  <p className="text-xs text-gray-500 uppercase tracking-wide">
                    {book.genre}
                  </p>
                </div>
              </Link>
            ))}
          </div>

          {/* No Books Found */}
          {books.length === 0 && !loading && (
            <div className="text-center py-16">
              <div className="text-gray-400 mb-4">
                <FiSearch size={48} className="mx-auto" />
              </div>
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                No books found
              </h3>
              <p className="text-gray-600">
                {searchTerm
                  ? `No books match your search for "${searchTerm}"`
                  : 'No books are available at the moment'
                }
              </p>
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex justify-center items-center space-x-2 mt-12">
              <button
                onClick={() => handlePageChange(currentPage - 1)}
                disabled={currentPage === 1}
                className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <FiChevronLeft />
                Previous
              </button>

              <div className="flex space-x-1">
                {Array.from({ length: totalPages }, (_, i) => i + 1).map((page) => (
                  <button
                    key={page}
                    onClick={() => handlePageChange(page)}
                    className={`px-3 py-2 rounded-lg transition duration-200 ${
                      page === currentPage
                        ? 'bg-blue-600 text-white'
                        : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
                    }`}
                  >
                    {page}
                  </button>
                ))}
              </div>

              <button
                onClick={() => handlePageChange(currentPage + 1)}
                disabled={currentPage === totalPages}
                className="btn-secondary disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
                <FiChevronRight />
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
};

export default BooksPage;
