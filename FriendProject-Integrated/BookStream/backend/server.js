const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const connectDB = require('./config/db');

// Load environment variables
dotenv.config();

// Connect to database
connectDB();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Routes

const User = require('./models/User');
const Book = require('./models/Book');
const serviceAdmin = (req,res,next) => {
  const key = process.env.CLOUDSENTINEL_SERVICE_KEY || 'dev-integration-key';
  if (req.headers['x-cloudsentinel-service-key'] !== key) return res.status(401).json({message:'Unauthorized'});
  next();
};
app.get('/api/integration/admin/users', serviceAdmin, async (req,res)=>res.json(await User.find().select('-password')));
app.patch('/api/integration/admin/users/:id', serviceAdmin, async (req,res)=>{
  const allowed={status:['ACTIVE','FROZEN','BLOCKED'],role:['user','admin']}; const update={};
  for(const k of Object.keys(allowed)) if(req.body[k] && allowed[k].includes(req.body[k])) update[k]=req.body[k];
  if(req.body.forcePasswordChange !== undefined) update.forcePasswordChange=!!req.body.forcePasswordChange;
  const user=await User.findByIdAndUpdate(req.params.id,update,{new:true}).select('-password');
  if(!user) return res.status(404).json({message:'User not found'}); res.json(user);
});
app.get('/api/integration/admin/books', serviceAdmin, async (req,res)=>res.json(await Book.find().sort({createdAt:-1})));
app.delete('/api/integration/admin/books/:id', serviceAdmin, async (req,res)=>{
  const book=await Book.findById(req.params.id); if(!book) return res.status(404).json({message:'Book not found'}); await book.deleteOne(); res.json({message:'Book deleted'});
});
app.use('/api/auth', require('./routes/authRoutes'));
app.get('/api/health', (req,res)=>res.json({ok:true, service:'BookStream'}));
app.use('/api/books', require('./routes/bookRoutes'));
app.use('/api/ratings', require('./routes/ratingRoutes'));
app.use('/api/bookmarks', require('./routes/bookmarkRoutes'));

// Create uploads directories if they don't exist
const fs = require('fs');
const uploadsDir = path.join(__dirname, 'uploads');
const coversDir = path.join(__dirname, 'uploads', 'covers');
const pdfsDir = path.join(__dirname, 'uploads', 'pdfs');

if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir);
}
if (!fs.existsSync(coversDir)) {
  fs.mkdirSync(coversDir);
}
if (!fs.existsSync(pdfsDir)) {
  fs.mkdirSync(pdfsDir);
}

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
