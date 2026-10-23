const mongoose = require('mongoose');

const ratingSchema = new mongoose.Schema({
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
  rating: {
    type: Number,
    required: true,
    min: 1,
    max: 5,
  },
}, {
  timestamps: true,
});

// Compound index to ensure one rating per user per book
ratingSchema.index({ book: 1, user: 1 }, { unique: true });

module.exports = mongoose.model('Rating', ratingSchema);
