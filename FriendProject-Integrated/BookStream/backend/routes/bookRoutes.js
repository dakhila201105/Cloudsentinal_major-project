const express = require('express');
const router = express.Router();
const {
  uploadBook,
  getBooks,
  getBookById,
  downloadBook,
  deleteBook,
} = require('../controllers/bookController');
const { protect, admin, optionalProtect } = require('../middleware/auth');
const upload = require('../middleware/upload');

router.route('/')
  .get(optionalProtect, getBooks)
  .post(
    protect,
    admin,
    upload.fields([
      { name: 'coverImage', maxCount: 1 },
      { name: 'pdfFile', maxCount: 1 }
    ]),
    uploadBook
  );

router.route('/:id')
  .get(optionalProtect, getBookById)
  .delete(protect, admin, deleteBook);

router.get('/:id/download', protect, downloadBook);

module.exports = router;
