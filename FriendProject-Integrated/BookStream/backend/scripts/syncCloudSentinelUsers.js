const path = require('path');
const dotenv = require('dotenv');
const mongoose = require('mongoose');

dotenv.config({ path: path.join(__dirname, '..', '.env'), override: true });

const User = require('../models/User');
const cloudSentinel = require('../services/cloudSentinel');

async function syncUsers() {
  if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is missing from backend/.env');
  await mongoose.connect(process.env.MONGODB_URI);
  const users = await User.find({}).select('firstName lastName email role');
  let synced = 0;
  for (const user of users) {
    await cloudSentinel.registerUser(user);
    synced += 1;
  }
  console.log(`CloudSentinel identities synchronized: ${synced}.`);
}

syncUsers()
  .catch(error => {
    console.error('CloudSentinel identity sync failed:', error.response?.data || error.message);
    process.exitCode = 1;
  })
  .finally(async () => {
    if (mongoose.connection.readyState) await mongoose.disconnect();
  });
