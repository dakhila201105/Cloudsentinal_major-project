# BookStream – Ebook Platform

A complete MERN stack ebook platform where users can read, download, and bookmark books online.

## ✨ Features
- 🌟 **Beautiful Landing Page** with modern design and animations
- 📚 **Browse & Search Books** with pagination and filtering
- 📖 **Online Book Reader** with PDF viewing, zoom, and rotation
- 🔖 **Bookmark System** to save favorite pages
- ⭐ **Rating System** to rate and review books
- 📥 **Download Books** in PDF format
- 🔐 **User Authentication** with JWT tokens
- 👑 **Admin Panel** for uploading new books
- 📱 **Fully Responsive** design for all devices
- 🎨 **Modern UI** with Tailwind CSS and smooth animations

## 🛠 Tech Stack
- **Frontend**: React.js, Tailwind CSS, React Router, React-PDF, Axios
- **Backend**: Node.js, Express.js, JWT Authentication
- **Database**: MongoDB with Mongoose ODM
- **File Storage**: Local uploads with Multer
- **State Management**: React Context API
- **Icons**: React Icons

## 📁 Project Structure
```
BookStream/
├── backend/
│   ├── config/
│   │   └── db.js                 # MongoDB connection
│   ├── controllers/
│   │   ├── authController.js     # Authentication logic
│   │   ├── bookController.js     # Book management
│   │   ├── ratingController.js   # Rating system
│   │   └── bookmarkController.js # Bookmark system
│   ├── middleware/
│   │   ├── auth.js               # JWT authentication
│   │   └── upload.js             # File upload handling
│   ├── models/
│   │   ├── User.js               # User schema
│   │   ├── Book.js               # Book schema
│   │   ├── Rating.js             # Rating schema
│   │   └── Bookmark.js           # Bookmark schema
│   ├── routes/
│   │   ├── authRoutes.js         # Auth routes
│   │   ├── bookRoutes.js         # Book routes
│   │   ├── ratingRoutes.js       # Rating routes
│   │   └── bookmarkRoutes.js     # Bookmark routes
│   ├── uploads/                  # File storage
│   │   ├── covers/               # Book cover images
│   │   └── pdfs/                 # PDF files
│   ├── .env                      # Environment variables
│   ├── .env.example              # Environment template
│   ├── package.json              # Backend dependencies
│   └── server.js                 # Express server
├── frontend/
│   ├── public/
│   │   └── index.html            # HTML template
│   ├── src/
│   │   ├── components/
│   │   │   ├── Navbar.js         # Navigation bar
│   │   │   └── PrivateRoute.js   # Route protection
│   │   ├── context/
│   │   │   └── AuthContext.js    # Authentication context
│   │   ├── pages/
│   │   │   ├── LandingPage.js    # Home page
│   │   │   ├── BooksPage.js      # Books listing
│   │   │   ├── AuthPage.js       # Login/Register
│   │   │   ├── BookReaderPage.js # PDF reader
│   │   │   ├── BookmarksPage.js  # User bookmarks
│   │   │   └── UploadBooksPage.js # Admin upload
│   │   ├── services/
│   │   │   └── api.js            # API service
│   │   ├── App.js                # Main React app
│   │   ├── index.js              # React entry point
│   │   ├── index.css             # Global styles
│   │   └── tailwind.config.js    # Tailwind config
│   └── package.json              # Frontend dependencies
└── README.md                     # This file
```

## 🚀 Installation & Setup

### Prerequisites
- Node.js (v14 or higher)
- MongoDB Atlas account (free tier available)
- npm or yarn

### Backend Setup
```bash
# Navigate to backend directory
cd backend

# Install dependencies
npm install

# Create environment file (already created)
# The .env file is already configured with default values

# Start the backend server
npm start
# or for development with auto-restart
npm run dev
```

### Frontend Setup
```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start the development server
npm start
```

### MongoDB Atlas Setup

1. **Create MongoDB Atlas Account**
   - Go to [MongoDB Atlas](https://www.mongodb.com/atlas) and create a free account
   - Create a new cluster (free tier is sufficient)
   - Wait for the cluster to be ready (usually 5-10 minutes)

2. **Get Connection String**
   - In your Atlas dashboard, click "Connect"
   - Choose "Connect your application"
   - Copy the connection string

3. **Update Environment Variables**
   - Replace the `MONGODB_URI` in `backend/.env` with your Atlas connection string
   - Replace `<username>`, `<password>`, and `<cluster-url>` with your actual values

   Example:
   ```
   MONGODB_URI=mongodb+srv://myuser:mypassword@cluster0.abcde.mongodb.net/bookstream?retryWrites=true&w=majority
   ```

4. **Configure Database Access**
   - In Atlas, go to "Database Access" and create a user
   - Go to "Network Access" and add your IP address (or allow all for development)

### Environment Configuration
The backend `.env` file is already configured with:
```
PORT=5000
MONGODB_URI=mongodb+srv://username:password@cluster0.xxxxx.mongodb.net/bookstream?retryWrites=true&w=majority
JWT_SECRET=your_super_secret_jwt_key_change_this_in_production_123456789
NODE_ENV=development
```

**Note**: For production, change the JWT_SECRET to a secure random string.

## 🎯 Usage

### Creating an Admin Account
To access admin features (uploading books), register with an email ending in `@admin.com`. For example:
- Email: `admin@admin.com`
- Password: `password123`

### Default Ports
- **Frontend**: http://localhost:3000
- **Backend**: http://localhost:5000

### API Endpoints
- `GET /api/books` - Get all books (with pagination and search)
- `POST /api/auth/register` - User registration
- `POST /api/auth/login` - User login
- `GET /api/auth/me` - Get current user (protected)
- `POST /api/books` - Upload book (admin only)
- `GET /api/books/:id` - Get book details
- `GET /api/books/:id/download` - Download book PDF (protected)
- `POST /api/ratings` - Rate a book (protected)
- `POST /api/bookmarks` - Add bookmark (protected)
- `GET /api/bookmarks` - Get user bookmarks (protected)

## 🎨 Features Overview

### Landing Page
- Modern hero section with call-to-action
- Feature showcase with icons and descriptions
- Responsive design with smooth animations

### Books Page
- Grid layout with book covers and details
- Search functionality (title and author)
- Pagination for large book collections
- Star ratings display

### Authentication
- Sign up with first name, last name, email, password
- Sign in with email and password
- Form validation and error handling
- Admin role detection based on email domain

### Book Reader
- PDF viewer with page navigation
- Zoom in/out and rotation controls
- Bookmark pages functionality
- Rating system integration
- Download PDF option

### Bookmarks
- View all bookmarked pages grouped by book
- Quick navigation to specific pages
- Delete bookmarks functionality

### Admin Panel
- Upload books with cover images and PDFs
- Form validation for all fields
- File type and size validation
- Success/error feedback

## 🔧 Development

### Available Scripts

#### Backend
```bash
npm start          # Start production server
npm run dev        # Start development server with nodemon
```

#### Frontend
```bash
npm start          # Start development server
npm run build      # Build for production
npm test           # Run tests
npm run eject      # Eject from Create React App
```

### File Upload Limits
- **Cover Images**: Up to 50MB (images only)
- **PDF Files**: Up to 50MB (PDFs only)
- Files are stored in `backend/uploads/` directory

## 🐛 Troubleshooting

### Common Issues

1. **MongoDB Atlas Connection Error**
   - Verify your username and password in the connection string
   - Check if your IP address is whitelisted in Atlas Network Access
   - Ensure the database user has the correct permissions
   - Test the connection string in MongoDB Compass first

2. **Port Already in Use**
   - Change PORT in .env file
   - Or kill process using the port

3. **PDF Not Loading**
   - Check if PDF file exists in uploads/pdfs/
   - Ensure react-pdf is properly installed
   - Verify PDF file is not corrupted

4. **Authentication Issues**
   - Clear localStorage if tokens are corrupted
   - Check JWT_SECRET in .env file
   - Ensure token hasn't expired

5. **File Upload Issues**
   - Check uploads directory permissions
   - Verify file size limits (50MB max)
   - Ensure proper file formats (images for covers, PDF for books)

### Development Tips
- Use browser developer tools to debug API calls
- Check server console for backend errors
- Verify file permissions for uploads directory

## 📄 License

MIT License - feel free to use this project for learning and development purposes.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

If you encounter any issues or have questions:
1. Check the troubleshooting section above
2. Review the code comments for implementation details
3. Create an issue in the repository

---

**Happy Reading! 📚✨**
