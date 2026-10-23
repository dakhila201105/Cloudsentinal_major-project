const Book = require('../models/Book');
const Rating = require('../models/Rating');
const fs = require('fs');
const path = require('path');
const cloudSentinel = require('../services/cloudSentinel');

// @desc    Upload a new book
// @route   POST /api/books
// @access  Private/Admin
const uploadBook = async (req, res) => {
  try {
    const { title, author, genre, description, totalPages } = req.body;

    if (!req.files || !req.files.coverImage || !req.files.pdfFile) {
      return res.status(400).json({ message: 'Please upload both cover image and PDF file' });
    }

    const book = await Book.create({
      title,
      author,
      genre,
      description,
      coverImage: req.files.coverImage[0].path,
      pdfFile: req.files.pdfFile[0].path,
      totalPages: totalPages || 100,
      uploadedBy: req.user._id,
    });

    await cloudSentinel.event(req.user, req, 'BOOK_UPLOAD', { resource_id: String(book._id), resource_name: book.title });
    res.status(201).json({
      message: 'The Book is uploaded successfully',
      book,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Upload failed', error: error.message });
  }
};

// @desc    Get all books with pagination and search
// @route   GET /api/books
// @access  Public
const getBooks = async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 12;
    const search = req.query.search || '';

    const query = search
      ? {
          $or: [
            { title: { $regex: search, $options: 'i' } },
            { author: { $regex: search, $options: 'i' } },
          ],
        }
      : {};

    const books = await Book.find(query)
      .populate('uploadedBy', 'firstName lastName')
      .sort({ createdAt: -1 })
      .limit(limit)
      .skip((page - 1) * limit);

    const count = await Book.countDocuments(query);

    if (req.user) {
      const eventType = search ? 'BOOK_SEARCH' : 'BOOK_LIST';
      cloudSentinel.event(req.user, req, eventType, { metadata: { search, page, limit } });
    }
    res.json({
      books,
      totalPages: Math.ceil(count / limit),
      currentPage: page,
      totalBooks: count,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Get single book by ID
// @route   GET /api/books/:id
// @access  Public
const getBookById = async (req, res) => {
  try {
    const book = await Book.findById(req.params.id).populate('uploadedBy', 'firstName lastName');

    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    if (req.user) cloudSentinel.event(req.user, req, 'BOOK_VIEW', { resource_id: String(book._id), resource_name: book.title });
    res.json(book);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Download book PDF
// @route   GET /api/books/:id/download
// @access  Private
const downloadBook = async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);

    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    const filePath = path.join(__dirname, '..', book.pdfFile);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ message: 'File not found' });
    }

    cloudSentinel.event(req.user, req, 'PDF_DOWNLOAD', { resource_id: String(book._id), resource_name: book.title, session_id: req.securitySessionId });
    res.download(filePath, `${book.title}.pdf`);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

// @desc    Delete a book
// @route   DELETE /api/books/:id
// @access  Private/Admin
const deleteBook = async (req, res) => {
  try {
    const book = await Book.findById(req.params.id);

    if (!book) {
      return res.status(404).json({ message: 'Book not found' });
    }

    // Delete files
    if (fs.existsSync(book.coverImage)) {
      fs.unlinkSync(book.coverImage);
    }
    if (fs.existsSync(book.pdfFile)) {
      fs.unlinkSync(book.pdfFile);
    }

    await book.deleteOne();
    await cloudSentinel.event(req.user, req, 'BOOK_DELETE', { resource_id: String(req.params.id), resource_name: book.title });
    res.json({ message: 'Book deleted successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
};

module.exports = {
  uploadBook,
  getBooks,
  getBookById,
  downloadBook,
  deleteBook,
};
