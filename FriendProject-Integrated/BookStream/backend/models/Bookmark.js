const mongoose = require('mongoose');

const bookmarkSchema = new mongoose.Schema({
  book: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Book',
    required: true,
  },
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  pageNumber: {
    type: Number,
    required: true,
    min: 1,
  },
}, {
  timestamps: true,
});

// Compound index to ensure one bookmark per user per page per book
bookmarkSchema.index({ book: 1, user: 1, pageNumber: 1 }, { unique: true });

module.exports = mongoose.model('Bookmark', bookmarkSchema);
