import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { FiUpload, FiFile, FiImage, FiX, FiCheck } from 'react-icons/fi';
import { booksAPI } from '../services/api';

const UploadBooksPage = () => {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    title: '',
    author: '',
    genre: '',
    description: '',
    totalPages: '',
  });
  const [files, setFiles] = useState({
    coverImage: null,
    pdfFile: null,
  });
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState({});
  const [success, setSuccess] = useState(false);

  const genres = [
    'Fiction',
    'Non-Fiction',
    'Mystery',
    'Romance',
    'Science Fiction',
    'Fantasy',
    'Biography',
    'History',
    'Self-Help',
    'Health',
    'Technology',
    'Business',
    'Children',
    'Young Adult',
    'Poetry',
    'Drama',
    'Other',
  ];

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData({
      ...formData,
      [name]: value,
    });
    // Clear error when user starts typing
    if (errors[name]) {
      setErrors({
        ...errors,
        [name]: '',
      });
    }
  };

  const handleFileChange = (e) => {
    const { name, files: selectedFiles } = e.target;
    if (selectedFiles.length > 0) {
      setFiles({
        ...files,
        [name]: selectedFiles[0],
      });
      // Clear error when user selects a file
      if (errors[name]) {
        setErrors({
          ...errors,
          [name]: '',
        });
      }
    }
  };

  const removeFile = (fileType) => {
    setFiles({
      ...files,
      [fileType]: null,
    });
    // Clear the file input
    const input = document.getElementById(fileType);
    if (input) {
      input.value = '';
    }
  };

  const validateForm = () => {
    const newErrors = {};

    if (!formData.title.trim()) {
      newErrors.title = 'Book title is required';
    }
    if (!formData.author.trim()) {
      newErrors.author = 'Author name is required';
    }
    if (!formData.genre) {
      newErrors.genre = 'Genre is required';
    }
    if (!formData.description.trim()) {
      newErrors.description = 'Description is required';
    }
    if (!formData.totalPages || formData.totalPages < 1) {
      newErrors.totalPages = 'Valid number of pages is required';
    }
    if (!files.coverImage) {
      newErrors.coverImage = 'Cover image is required';
    }
    if (!files.pdfFile) {
      newErrors.pdfFile = 'PDF file is required';
    }

    // Validate file types
    if (files.coverImage && !files.coverImage.type.startsWith('image/')) {
      newErrors.coverImage = 'Cover image must be an image file';
    }
    if (files.pdfFile && files.pdfFile.type !== 'application/pdf') {
      newErrors.pdfFile = 'Book file must be a PDF';
    }

    // Validate file sizes (50MB limit)
    if (files.coverImage && files.coverImage.size > 50 * 1024 * 1024) {
      newErrors.coverImage = 'Cover image must be less than 50MB';
    }
    if (files.pdfFile && files.pdfFile.size > 50 * 1024 * 1024) {
      newErrors.pdfFile = 'PDF file must be less than 50MB';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    if (!validateForm()) {
      return;
    }

    setLoading(true);

    try {
      const uploadData = new FormData();
      uploadData.append('title', formData.title);
      uploadData.append('author', formData.author);
      uploadData.append('genre', formData.genre);
      uploadData.append('description', formData.description);
      uploadData.append('totalPages', formData.totalPages);
      uploadData.append('coverImage', files.coverImage);
      uploadData.append('pdfFile', files.pdfFile);

      await booksAPI.uploadBook(uploadData);
      setSuccess(true);

      // Reset form after successful upload
      setTimeout(() => {
        setFormData({
          title: '',
          author: '',
          genre: '',
          description: '',
          totalPages: '',
        });
        setFiles({
          coverImage: null,
          pdfFile: null,
        });
        setErrors({});
        setSuccess(false);
        navigate('/books');
      }, 2000);

    } catch (error) {
      console.error('Error uploading book:', error);
      setErrors({
        submit: error.response?.data?.message || 'Failed to upload book. Please try again.'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8">
      {/* Header */}
      <div className="text-center animate-fade-in">
        <h1 className="text-4xl font-bold text-gray-900 mb-4">Upload New Book</h1>
        <p className="text-lg text-gray-600">
          Share a new book with the BookStream community
        </p>
      </div>

      {/* Success Message */}
      {success && (
        <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg animate-fade-in">
          <div className="flex items-center">
            <FiCheck className="mr-2" />
            The Book is uploaded successfully! Redirecting to books page...
          </div>
        </div>
      )}

      <div className="card animate-slide-up">
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Title */}
          <div>
            <label htmlFor="title" className="block text-sm font-medium text-gray-700 mb-1">
              Book Title *
            </label>
            <input
              type="text"
              id="title"
              name="title"
              value={formData.title}
              onChange={handleInputChange}
              className={`input-field ${errors.title ? 'border-red-500 focus:ring-red-500' : ''}`}
              placeholder="Enter book title"
            />
            {errors.title && (
              <p className="text-red-500 text-xs mt-1">{errors.title}</p>
            )}
          </div>

          {/* Author */}
          <div>
            <label htmlFor="author" className="block text-sm font-medium text-gray-700 mb-1">
              Author *
            </label>
            <input
              type="text"
              id="author"
              name="author"
              value={formData.author}
              onChange={handleInputChange}
              className={`input-field ${errors.author ? 'border-red-500 focus:ring-red-500' : ''}`}
              placeholder="Enter author name"
            />
            {errors.author && (
              <p className="text-red-500 text-xs mt-1">{errors.author}</p>
            )}
          </div>

          {/* Genre */}
          <div>
            <label htmlFor="genre" className="block text-sm font-medium text-gray-700 mb-1">
              Genre *
            </label>
            <select
              id="genre"
              name="genre"
              value={formData.genre}
              onChange={handleInputChange}
              className={`input-field ${errors.genre ? 'border-red-500 focus:ring-red-500' : ''}`}
            >
              <option value="">Select a genre</option>
              {genres.map((genre) => (
                <option key={genre} value={genre}>
                  {genre}
                </option>
              ))}
            </select>
            {errors.genre && (
              <p className="text-red-500 text-xs mt-1">{errors.genre}</p>
            )}
          </div>

          {/* Description */}
          <div>
            <label htmlFor="description" className="block text-sm font-medium text-gray-700 mb-1">
              Description *
            </label>
            <textarea
              id="description"
              name="description"
              rows={4}
              value={formData.description}
              onChange={handleInputChange}
              className={`input-field resize-none ${errors.description ? 'border-red-500 focus:ring-red-500' : ''}`}
              placeholder="Enter book description"
            />
            {errors.description && (
              <p className="text-red-500 text-xs mt-1">{errors.description}</p>
            )}
          </div>

          {/* Total Pages */}
          <div>
            <label htmlFor="totalPages" className="block text-sm font-medium text-gray-700 mb-1">
              Total Pages *
            </label>
            <input
              type="number"
              id="totalPages"
              name="totalPages"
              min="1"
              value={formData.totalPages}
              onChange={handleInputChange}
              className={`input-field ${errors.totalPages ? 'border-red-500 focus:ring-red-500' : ''}`}
              placeholder="Enter number of pages"
            />
            {errors.totalPages && (
              <p className="text-red-500 text-xs mt-1">{errors.totalPages}</p>
            )}
          </div>

          {/* Cover Image Upload */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Cover Image *
            </label>
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-400 transition duration-200">
              <input
                type="file"
                id="coverImage"
                name="coverImage"
                accept="image/*"
                onChange={handleFileChange}
                className="hidden"
              />
              <label htmlFor="coverImage" className="cursor-pointer">
                {files.coverImage ? (
                  <div className="space-y-2">
                    <div className="flex items-center justify-center space-x-2">
                      <FiImage className="text-green-600" />
                      <span className="text-green-600 font-medium">
                        {files.coverImage.name}
                      </span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.preventDefault();
                          removeFile('coverImage');
                        }}
                        className="text-red-500 hover:text-red-700"
                      >
                        <FiX />
                      </button>
                    </div>
                    <p className="text-sm text-gray-500">
                      {(files.coverImage.size / 1024 / 1024).toFixed(2)} MB
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <FiImage className="mx-auto text-gray-400 text-2xl" />
                    <p className="text-gray-600">Click to upload cover image</p>
                    <p className="text-sm text-gray-500">PNG, JPG up to 50MB</p>
                  </div>
                )}
              </label>
            </div>
            {errors.coverImage && (
              <p className="text-red-500 text-xs mt-1">{errors.coverImage}</p>
            )}
          </div>

          {/* PDF File Upload */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              PDF File *
            </label>
            <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-blue-400 transition duration-200">
              <input
                type="file"
                id="pdfFile"
                name="pdfFile"
                accept=".pdf"
                onChange={handleFileChange}
                className="hidden"
              />
              <label htmlFor="pdfFile" className="cursor-pointer">
                {files.pdfFile ? (
                  <div className="space-y-2">
                    <div className="flex items-center justify-center space-x-2">
                      <FiFile className="text-green-600" />
                      <span className="text-green-600 font-medium">
                        {files.pdfFile.name}
                      </span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.preventDefault();
                          removeFile('pdfFile');
                        }}
                        className="text-red-500 hover:text-red-700"
                      >
                        <FiX />
                      </button>
                    </div>
                    <p className="text-sm text-gray-500">
                      {(files.pdfFile.size / 1024 / 1024).toFixed(2)} MB
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <FiFile className="mx-auto text-gray-400 text-2xl" />
                    <p className="text-gray-600">Click to upload PDF file</p>
                    <p className="text-sm text-gray-500">PDF up to 50MB</p>
                  </div>
                )}
              </label>
            </div>
            {errors.pdfFile && (
              <p className="text-red-500 text-xs mt-1">{errors.pdfFile}</p>
            )}
          </div>

          {/* Submit Error */}
          {errors.submit && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg">
              {errors.submit}
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full btn-primary disabled:opacity-50 disabled:cursor-not-allowed py-3 flex items-center justify-center"
          >
            {loading ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-2"></div>
                Uploading Book...
              </>
            ) : (
              <>
                <FiUpload className="mr-2" />
                Upload Book
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default UploadBooksPage;
