// Import required modules
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');

// Initialize dotenv for environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Middleware setup
app.use(cors());
app.use(bodyParser.json()); // Parse JSON bodies

// MongoDB connection
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch((err) => console.log('MongoDB connection error:', err));

// Define User model
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  points: { type: Number, default: 0 },
  tier: { type: String, default: 'Bronze' },
  referralCode: { type: String },
  referredBy: { type: String },
});

const User = mongoose.model('User', userSchema);

// Middleware for JWT authentication
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).send('Access Denied');
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid Token');
    req.user = user;
    next();
  });
};

// Sign-up route
app.post('/signup', async (req, res) => {
  const { email, password, referralCode } = req.body;
  
  if (!email || !password) {
    return res.status(400).send('Email and Password are required');
  }

  const existingUser = await User.findOne({ email });
  if (existingUser) return res.status(400).send('User already exists');

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({
    email,
    password: hashedPassword,
    referralCode: Math.random().toString(36).substr(2, 9), // generate referral code
  });

  if (referralCode) {
    const referrer = await User.findOne({ referralCode });
    if (referrer) {
      user.referredBy = referrer.email;
      referrer.points += 10; // Increase referrer's points
      await referrer.save();
    }
  }

  await user.save();
  const token = jwt.sign({ _id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.status(201).send({ token });
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });

  if (!user) return res.status(400).send('User not found');

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) return res.status(400).send('Invalid password');

  const token = jwt.sign({ _id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.status(200).send({ token });
});

// Update points route
app.post('/logRide', authMiddleware, async (req, res) => {
  const { points } = req.body;
  if (!points || points < 1) return res.status(400).send('Invalid points');

  const user = await User.findById(req.user._id);
  user.points += points;

  // Determine tier based on points
  if (user.points >= 100) {
    user.tier = 'Gold';
  } else if (user.points >= 50) {
    user.tier = 'Silver';
  } else {
    user.tier = 'Bronze';
  }

  await user.save();
  res.status(200).send({ points: user.points, tier: user.tier });
});

// Protected route for user data
app.get('/dashboard', authMiddleware, async (req, res) => {
  const user = await User.findById(req.user._id);
  res.status(200).send({
    email: user.email,
    points: user.points,
    tier: user.tier,
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
