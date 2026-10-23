const mongoose = require('mongoose');

const bookSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, 'Please provide book title'],
    trim: true,
  },
  author: {
    type: String,
    required: [true, 'Please provide author name'],
    trim: true,
  },
  genre: {
    type: String,
    required: [true, 'Please provide genre'],
    trim: true,
  },
  description: {
    type: String,
    required: [true, 'Please provide description'],
  },
  coverImage: {
    type: String,
    required: [true, 'Please provide cover image'],
  },
  pdfFile: {
    type: String,
    required: [true, 'Please provide PDF file'],
  },
  totalPages: {
    type: Number,
    default: 0,
  },
  averageRating: {
    type: Number,
    default: 0,
  },
  totalRatings: {
    type: Number,
    default: 0,
  },
  uploadedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    default: null,
  },
}, {
  timestamps: true,
});

module.exports = mongoose.model('Book', bookSchema);
