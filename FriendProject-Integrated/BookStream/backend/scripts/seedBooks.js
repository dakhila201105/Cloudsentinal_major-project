const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');
const Book = require('../models/Book');

dotenv.config({ path: path.join(__dirname, '..', '.env') });

const catalog = [
  ['1761142491907', 'B.E. Artificial Intelligence and Data Science Syllabus (R-22)', 'Chaitanya Bharathi Institute of Technology', 'Education', 'Course scheme and syllabus for the B.E. / B.Tech. Artificial Intelligence and Data Science program.', 218],
  ['1761496926866', 'Data Analyst Roadmap', 'Rohan Das', 'Career', 'A practical roadmap covering the skills and resources needed to begin a career in data analytics.', 1],
  ['1761497468028', 'DBMS & SQL Notes', 'Not listed', 'Computer Science', 'Notes introducing databases, database management systems, and SQL.', 27],
  ['1761498363631', 'The Complete Data Science Roadmap', 'Mosh Hamedani', 'Data Science', 'A roadmap for progressing from beginner to data scientist, with a suggested 12-month learning path.', 21],
  ['1761498534941', 'Top 50 Database (DBMS) Interview Questions & Answers', 'Prasad Rathod', 'Interview Prep', 'Common database and DBMS interview questions with concise answers.', 10],
  ['1761498722444', 'HR Interview Questions and Answers', 'Chetan Singh', 'Interview Prep', 'A collection of human resources interview questions and sample answers.', 15],
  ['1761498862315', 'Java Collections Framework', 'Rahul Neha', 'Programming', 'An illustrated overview of Java collection interfaces, classes, and common methods.', 7],
  ['1761499093516', 'Java Interview Questions and Answers', 'Pratik Bandal', 'Interview Prep', 'Java interview preparation questions and answers, including core Java topics.', 28],
  ['1761499484680', 'Python 3 Object-Oriented Programming', 'Dusty Phillips', 'Programming', 'A detailed guide to object-oriented programming concepts and techniques in Python 3.', 964],
  ['1761499758527', 'SQL Interview Questions', 'Prasad Rathod', 'Interview Prep', 'A collection of SQL interview questions and answers for database roles.', 12],
  ['1761500169276', 'SQL (Structured Query Language) Database', 'Nayan Hossen', 'Databases', 'A reference to SQL concepts, database design, and working with structured data.', 138],
  ['1761500444111', 'Complete Core Java Notes', 'Code Buddy', 'Programming', 'Core Java notes covering foundational language concepts and examples.', 87],
  ['1761506265218', 'A Cry of Innocence', 'Peter C. Byrnes', 'Mystery', 'A senior detective story featuring Joseph Lind and Angelica “Angie” De Longo.', 103],
  ['1761506452640', 'Battle of the River Plate', 'Pat Fogwill', 'History', 'A compilation of documents about the Battle of the River Plate.', 34],
  ['1761506687260', 'Fragmented Control (Tempestria 4)', 'Gary Stringer', 'Fantasy', 'The fourth Tempestria novel, following a struggle over control of the realm.', 290],
  ['1761506907920', 'History Makers: Richard III', 'Jacob Abbott', 'History', 'A biography of Richard III from Jacob Abbott’s History Makers series.', 179],
  ['1761507099211', 'Lake District Poems (2005–2023)', 'Wendy Webb', 'Poetry', 'A collection of poems written between 2005 and 2023, inspired by the Lake District.', 86],
];

function findAsset(directory, prefix, expectedStamp) {
  const candidates = fs.readdirSync(directory)
    .map(name => ({ name, stamp: Number(name.match(new RegExp(`^${prefix}-(\\d+)-`))?.[1]) }))
    .filter(file => Number.isFinite(file.stamp))
    .sort((a, b) => Math.abs(a.stamp - expectedStamp) - Math.abs(b.stamp - expectedStamp));
  if (!candidates.length || Math.abs(candidates[0].stamp - expectedStamp) > 10000) {
    throw new Error(`Missing project asset near ${prefix}-${expectedStamp} in ${directory}`);
  }
  return candidates[0].name;
}

async function seedBooks() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is missing from backend/.env');
  const backendDir = path.join(__dirname, '..');
  const coversDir = path.join(backendDir, 'uploads', 'covers');
  const pdfsDir = path.join(backendDir, 'uploads', 'pdfs');
  await mongoose.connect(process.env.MONGODB_URI);

  let inserted = 0;
  let alreadyPresent = 0;
  for (const [stamp, title, author, genre, description, totalPages] of catalog) {
    const coverName = findAsset(coversDir, 'coverImage', Number(stamp));
    const pdfName = findAsset(pdfsDir, 'pdfFile', Number(stamp));
    const pdfFile = path.posix.join('uploads', 'pdfs', pdfName);
    const existing = await Book.findOne({ pdfFile }).select('_id');
    if (existing) {
      alreadyPresent += 1;
      continue;
    }
    await Book.create({
      title,
      author,
      genre,
      description,
      totalPages,
      coverImage: path.posix.join('uploads', 'covers', coverName),
      pdfFile,
      uploadedBy: null,
    });
    inserted += 1;
  }
  console.log(`Catalog ready: ${inserted} added, ${alreadyPresent} already present.`);
}

seedBooks()
  .catch(error => {
    console.error('Book catalog import failed:', error.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    if (mongoose.connection.readyState) await mongoose.disconnect();
  });
