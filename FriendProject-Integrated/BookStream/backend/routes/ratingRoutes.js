const express = require('express');
const router = express.Router();
const {
  rateBook,
  getUserRating,
  deleteRating,
} = require('../controllers/ratingController');
const { protect } = require('../middleware/auth');

router.route('/')
  .post(protect, rateBook);

router.route('/:bookId')
  .get(protect, getUserRating)
  .delete(protect, deleteRating);

module.exports = router;
