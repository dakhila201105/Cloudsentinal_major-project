const Rating = require('../models/Rating');
const Book = require('../models/Book');
const cloudSentinel = require('../services/cloudSentinel');

// @desc    Rate a book
// @route   POST /api/ratings
// @access  Private
const rateBook = async (req, res) => {
  try {
    const { bookId, rating } = req.body;

    if (!bookId || !rating) {
      return res.status(400).json({ message: 'Please provide book ID and rating' });
    }

    if (rating < 1 || rating > 5) {
      return res.status(400).json({ message: 'Rating must be between 1 and 5' });
    }

    // Check if book exists
    const book = await Book.findById(bookId);
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    // Check if user already rated this book
    let existingRating = await Rating.findOne({
      book: bookId,
      user: req.user._id,
    });

    if (existingRating) {
      // Update existing rating
      existingRating.rating = rating;
      await existingRating.save();
    } else {
      // Create new rating
      existingRating = await Rating.create({
        book: bookId,
        user: req.user._id,
        rating,
      });
    }

    // Recalculate book's average rating
    const ratings = await Rating.find({ book: bookId });
    const totalRatings = ratings.length;
    const sumRatings = ratings.reduce((sum, r) => sum + r.rating, 0);
    const averageRating = totalRatings > 0 ? sumRatings / totalRatings : 0;

    book.averageRating = averageRating;
    book.totalRatings = totalRatings;
    await book.save();

    await cloudSentinel.event(req.user, req, 'RATING', { resource_id: String(book._id), resource_name: book.title, metadata: { rating } });
    res.json({
      message: 'Rating submitted successfully',
      rating: existingRating,
      bookAverageRating: averageRating,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Get user's rating for a book
// @route   GET /api/ratings/:bookId
// @access  Private
const getUserRating = async (req, res) => {
  try {
    const rating = await Rating.findOne({
      book: req.params.bookId,
      user: req.user._id,
    });

    if (!rating) {
      return res.json({ rating: null });
    }

    res.json(rating);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Delete user's rating
// @route   DELETE /api/ratings/:bookId
// @access  Private
const deleteRating = async (req, res) => {
  try {
    const rating = await Rating.findOne({
      book: req.params.bookId,
      user: req.user._id,
    });

    if (!rating) {
      return res.status(404).json({ message: 'Rating not found' });
    }

    await rating.deleteOne();

    // Recalculate book's average rating
    const book = await Book.findById(req.params.bookId);
    const ratings = await Rating.find({ book: req.params.bookId });
    const totalRatings = ratings.length;
    const sumRatings = ratings.reduce((sum, r) => sum + r.rating, 0);
    const averageRating = totalRatings > 0 ? sumRatings / totalRatings : 0;

    book.averageRating = averageRating;
    book.totalRatings = totalRatings;
    await book.save();

    res.json({ message: 'Rating deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

module.exports = {
  rateBook,
  getUserRating,
  deleteRating,
};
