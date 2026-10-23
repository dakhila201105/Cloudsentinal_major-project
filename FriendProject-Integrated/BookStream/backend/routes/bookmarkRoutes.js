const express = require('express');
const router = express.Router();
const {
  addBookmark,
  getBookmarks,
  getBookmarksByBook,
  deleteBookmark,
  deleteBookmarkByPage,
} = require('../controllers/bookmarkController');
const { protect } = require('../middleware/auth');

router.route('/')
  .post(protect, addBookmark)
  .get(protect, getBookmarks);

router.get('/:bookId', protect, getBookmarksByBook);

router.route('/:id')
  .delete(protect, deleteBookmark);

router.delete('/:bookId/:pageNumber', protect, deleteBookmarkByPage);

module.exports = router;
