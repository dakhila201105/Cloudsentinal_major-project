const Bookmark = require('../models/Bookmark');
const cloudSentinel = require('../services/cloudSentinel');
const Book = require('../models/Book');

// @desc    Add bookmark
// @route   POST /api/bookmarks
// @access  Private
const addBookmark = async (req, res) => {
  try {
    const { bookId, pageNumber } = req.body;

    if (!bookId || !pageNumber) {
      return res.status(400).json({ message: 'Please provide book ID and page number' });
    }

    // Check if book exists
    const book = await Book.findById(bookId);
    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    // Check if bookmark already exists
    const existingBookmark = await Bookmark.findOne({
      book: bookId,
      user: req.user._id,
      pageNumber,
    });

    if (existingBookmark) {
      return res.status(400).json({ message: 'Bookmark already exists for this page' });
    }

    const bookmark = await Bookmark.create({
      book: bookId,
      user: req.user._id,
      pageNumber,
    });

    const populatedBookmark = await Bookmark.findById(bookmark._id).populate('book', 'title author coverImage');

    await cloudSentinel.event(req.user, req, 'BOOKMARK_ADD', { resource_id: String(bookmark.book), metadata: { pageNumber: bookmark.pageNumber } });
    res.status(201).json({
      message: 'Bookmark added successfully',
      bookmark: populatedBookmark,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Get user's bookmarks
// @route   GET /api/bookmarks
// @access  Private
const getBookmarks = async (req, res) => {
  try {
    const bookmarks = await Bookmark.find({ user: req.user._id })
      .populate('book', 'title author coverImage totalPages')
      .sort({ createdAt: -1 });

    // Group bookmarks by book
    const groupedBookmarks = {};
    bookmarks.forEach((bookmark) => {
      const bookId = bookmark.book._id.toString();
      if (!groupedBookmarks[bookId]) {
        groupedBookmarks[bookId] = {
          book: bookmark.book,
          bookmarks: [],
        };
      }
      groupedBookmarks[bookId].bookmarks.push({
        _id: bookmark._id,
        pageNumber: bookmark.pageNumber,
        createdAt: bookmark.createdAt,
      });
    });

    res.json(Object.values(groupedBookmarks));
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Get bookmarks for a specific book
// @route   GET /api/bookmarks/:bookId
// @access  Private
const getBookmarksByBook = async (req, res) => {
  try {
    const bookmarks = await Bookmark.find({
      book: req.params.bookId,
      user: req.user._id,
    }).sort({ pageNumber: 1 });

    res.json(bookmarks);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Delete bookmark
// @route   DELETE /api/bookmarks/:id
// @access  Private
const deleteBookmark = async (req, res) => {
  try {
    const bookmark = await Bookmark.findOne({
      _id: req.params.id,
      user: req.user._id,
    });

    if (!bookmark) {
      return res.status(404).json({ message: 'Bookmark not found' });
    }

    await bookmark.deleteOne();
    await cloudSentinel.event(req.user, req, 'BOOKMARK_REMOVE', { resource_id: String(bookmark.book), metadata: { pageNumber: bookmark.pageNumber } });
    res.json({ message: 'Bookmark deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Delete bookmark by book and page
// @route   DELETE /api/bookmarks/:bookId/:pageNumber
// @access  Private
const deleteBookmarkByPage = async (req, res) => {
  try {
    const bookmark = await Bookmark.findOne({
      book: req.params.bookId,
      user: req.user._id,
      pageNumber: req.params.pageNumber,
    });

    if (!bookmark) {
      return res.status(404).json({ message: 'Bookmark not found' });
    }

    await bookmark.deleteOne();
    await cloudSentinel.event(req.user, req, 'BOOKMARK_REMOVE', { resource_id: String(bookmark.book), metadata: { pageNumber: bookmark.pageNumber } });
    res.json({ message: 'Bookmark deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

module.exports = {
  addBookmark,
  getBookmarks,
  getBookmarksByBook,
  deleteBookmark,
  deleteBookmarkByPage,
};
