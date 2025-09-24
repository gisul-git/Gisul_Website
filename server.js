const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const User = require('./User');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const Cart = require('./Cart');
const Wishlist = require('./Wishlist');
const MulterAzureStorage = require('multer-azure-blob-storage').MulterAzureStorage;
const Counter = require('./Counter');
const axios = require('axios');
const { OAuth2Client } = require('google-auth-library');
const helmet = require('helmet');
const hpp = require('hpp');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const { getConfig } = require('./config/env');

const TrainerApplication = require('./TrainerApplication');
const Order = require('./Order');
const Progress = require('./Progress');

const app = express();
app.set('trust proxy', 1);
const cfg = getConfig();
const PORT = process.env.PORT || 8080;
let dbReady = false;

// Fail-fast config validation helper
function requireKeys(obj, keys, name = 'config') {
  const missing = keys.filter(k => !obj || obj[k] === undefined || obj[k] === null || obj[k] === '');
  if (missing.length) {
    console.error(`Missing ${name} keys: ${missing.join(', ')}`);
    process.exit(1);
  }
}

// minimally required to boot
requireKeys(cfg, ['mongodbUri','jwtSecret'], 'root');

// Middleware
app.get('/healthz', (_req, res) => res.status(200).send('ok'));
app.get('/readyz', (_req, res) => res.status(dbReady ? 200 : 503).json({ dbReady }));
app.use(helmet());
app.use(hpp());
app.use(cors({
  origin: (cfg.allowedOrigins || []).filter(Boolean),
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(express.json());
if (cfg.logLevel === 'debug') {
  app.use(morgan('dev'));
} else if (cfg.logLevel === 'info') {
  app.use(morgan('tiny'));
}

// Global rate limiter
const limiter = rateLimit({
  windowMs: cfg.rateLimit?.windowMs || 60 * 1000,
  max: cfg.rateLimit?.maxRequestsPerWindow || 120,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Guard DB/session dependent routes during warmup
const requireDbReady = (req, res, next) => {
  if (!dbReady) return res.status(503).json({ message: 'Service warming up, try again in a moment.' });
  next();
};
app.use([
  '/login','/logout','/profile','/profile/picture',
  '/cart','/cart/add','/cart/update-quantity','/cart/remove',
  '/wishlist','/wishlist/add','/wishlist/remove',
  '/apply-trainer','/course/image',
  '/payment/success','/orders','/progress','/protected',
  '/auth/google','/auth/google/callback',
  '/signup'
], requireDbReady);

// Session middleware will be mounted AFTER Mongo connects

// Test route
app.get('/', (req, res) => {
  res.send('Signup backend is running!');
});

// Signup endpoint
app.post('/signup', async (req, res) => {
  try {
    const { email, username, phone, password } = req.body;

    // Basic validation for manual signup
    if (!email || !username || !phone || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(409).json({ message: 'Email or username already in use.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      email,
      username,
      phone,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json({ message: 'User registered successfully!' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { emailOrUsername, password } = req.body;

    // Basic validation
    if (!emailOrUsername || !password) {
      return res.status(400).json({ message: 'Email/Username and password are required.' });
    }

    // Find user by email or username
    const user = await User.findOne({
      $or: [{ email: emailOrUsername }, { username: emailOrUsername }]
    });

    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Check if user is OAuth-only (no password)
    if (!user.password) {
      return res.status(401).json({ message: 'This account was created with Google OAuth. Please use Google login.' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid credentials.' });
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email, username: user.username },
      cfg.jwtSecret,
      { expiresIn: '1h' }
    );

    // Set session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.email = user.email;

    res.status(200).json({ message: 'Login successful!', token, session: req.session });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Logout endpoint
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout error:', err);
      return res.status(500).json({ message: 'Logout failed.' });
    }
    res.clearCookie('connect.sid', { sameSite: 'None', secure: true, httpOnly: true });
    res.json({ message: 'Logged out successfully.' });
  });
});

// Google OAuth routes
app.get('/auth/google', (req, res) => {
  const googleAuthUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${cfg.google?.clientId || ''}&` +
    `redirect_uri=${encodeURIComponent(cfg.google?.redirectUri || '')}&` +
    `response_type=code&` +
    `scope=openid email profile&` +
    `access_type=offline&` +
    `prompt=consent`;
  
  res.redirect(googleAuthUrl);
});

app.get('/auth/google/callback', async (req, res) => {
  try {
    const { code } = req.query;
    
    if (!code) {
      return res.status(400).json({ message: 'Authorization code is required' });
    }


    // Exchange code for token
    const body = new URLSearchParams({
      client_id: cfg.google?.clientId || '',
      client_secret: cfg.google?.clientSecret || '',
      code: code,
      grant_type: 'authorization_code',
      redirect_uri: cfg.google?.redirectUri || ''
    });
    const tokenResponse = await axios.post(
      'https://oauth2.googleapis.com/token',
      body.toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const { access_token, id_token } = tokenResponse.data;

    // Verify and decode the ID token
    const client = new OAuth2Client(cfg.google?.clientId || '');
    const ticket = await client.verifyIdToken({
      idToken: id_token,
      audience: cfg.google?.clientId || ''
    });

    const payload = ticket.getPayload();
    const { email, name, given_name, family_name, picture } = payload;

    // Check if user already exists
    let user = await User.findOne({ email });

    if (!user) {
      // Create new user for OAuth
      const username = email.split('@')[0] + '_' + Math.random().toString(36).substr(2, 5);
      
      user = new User({
        email,
        username,
        phone: '', // OAuth users don't provide phone initially
        password: null, // OAuth users don't have passwords
        fullName: name || `${given_name || ''} ${family_name || ''}`.trim(),
        profilePic: picture || '',
        oauthProvider: 'google'
      });

      await user.save();
    } else {
      // Update existing user's OAuth info if needed
      if (!user.oauthProvider) {
        user.oauthProvider = 'google';
        if (!user.fullName && name) user.fullName = name;
        if (!user.profilePic && picture) user.profilePic = picture;
        await user.save();
      }
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email, username: user.username },
      cfg.jwtSecret,
      { expiresIn: '1h' }
    );

    // Set session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.email = user.email;

    // Redirect to frontend with token
    const base = cfg.frontendBaseUrl || 'https://gisul.co.in';
    res.redirect(`${base}/courses?token=${token}`);

  } catch (error) {
    console.error('Google OAuth callback error:', error);
    const base = cfg.frontendBaseUrl || 'https://gisul.co.in';
    res.redirect(`${base}/login-error?message=Authentication failed`);
  }
});

// Get user profile
app.get('/profile', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Not authenticated' });
    }
    const user = await User.findById(req.session.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json({
      _id: user._id, // <-- Add this line!
      email: user.email,
      username: user.username,
      fullName: user.fullName,
      phone: user.phone,
      gender: user.gender,
      country: user.country,
      language: user.language,
      timezone: user.timezone,
      profilePic: user.profilePic || ''
    });
  } catch (err) {
    console.error('Profile read error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Update user profile
app.put('/profile', async (req, res) => {
  try {
    if (!req.session.userId) {
      return res.status(401).json({ message: 'Not authenticated' });
    }

    const { fullName, phone, gender, country, language, timezone } = req.body;

    const user = await User.findById(req.session.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Update fields
    if (fullName !== undefined) user.fullName = fullName;
    if (phone !== undefined) user.phone = phone;
    if (gender !== undefined) user.gender = gender;
    if (country !== undefined) user.country = country;
    if (language !== undefined) user.language = language;
    if (timezone !== undefined) user.timezone = timezone;

    await user.save();

    res.json({ 
      message: 'Profile updated successfully',
      profile: {
        email: user.email,
        username: user.username,
        fullName: user.fullName,
        phone: user.phone,
        gender: user.gender,
        country: user.country,
        language: user.language,
        timezone: user.timezone
      }
    });
  } catch (err) {
    console.error('Profile update error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Removed local memory upload wiring; using Azure storage factories per route

// Note: Local file storage removed for Azure compatibility
// All file uploads should use Azure Blob Storage

// Azure Blob Storage lazy factory
function makeAzureStorage(containerName) {
  if (!cfg.azure?.storageConnectionString) {
    throw new Error('Azure Storage not configured');
  }
  return new MulterAzureStorage({
    connectionString: cfg.azure.storageConnectionString,
    containerName,
    blobName: (_req, file) => Date.now() + '-' + file.originalname,
    contentSettings: { contentType: (_req, file) => file.mimetype }
  });
}
const makeUpload = (container) => multer({ storage: makeAzureStorage(container) });

app.post('/profile/picture', (req, res, next) => {
  try {
    const uploadProfilePic = makeUpload(cfg.azure?.profileContainer || 'profile-pictures').single('profilePic');
    uploadProfilePic(req, res, next);
  } catch (e) {
    console.error(e.message);
    return res.status(503).json({ message: 'File storage not configured' });
  }
}, async (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ message: 'Not authenticated' });
  if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
  const imageUrl = req.file.url;
  await User.findByIdAndUpdate(req.session.userId, { profilePic: imageUrl });
  res.json({ message: 'Profile picture updated', profilePic: imageUrl });
});

// Add to cart
app.post('/cart/add', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: 'Not authenticated' });
  const { courseId, title, price, duration, imageUrl } = req.body; // Add imageUrl
  if (!courseId) return res.status(400).json({ message: 'Missing courseId' });

  let cart = await Cart.findOne({ userId: req.session.userId });
  if (!cart) {
    cart = new Cart({ userId: req.session.userId, items: [] });
  }
  // Check if course is already in cart
  const existingItem = cart.items.find(item => item.courseId === courseId);
  if (existingItem) {
    existingItem.quantity += 1; // Increment quantity if already in cart
  } else {
    cart.items.push({ courseId, title, price, duration, imageUrl, quantity: 1 });
  }
  await cart.save();
  res.json({ message: 'Added to cart', cart: cart.items });
});

// Get cart
app.get('/cart', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: 'Not authenticated' });
  const cart = await Cart.findOne({ userId: req.session.userId });
  res.json({ cart: cart ? cart.items : [] });
});

// Update quantity (increment or decrement)
app.post('/cart/update-quantity', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: 'Not authenticated' });
  const { courseId, action } = req.body; // action: 'increment' or 'decrement'
  if (!courseId || !['increment', 'decrement'].includes(action)) {
    return res.status(400).json({ message: 'Invalid request' });
  }

  const cart = await Cart.findOne({ userId: req.session.userId });
  if (!cart) return res.status(404).json({ message: 'Cart not found' });

  const item = cart.items.find(i => i.courseId === courseId);
  if (!item) return res.status(404).json({ message: 'Item not found in cart' });

  if (action === 'increment') {
    item.quantity += 1;
  } else if (action === 'decrement' && item.quantity > 1) {
    item.quantity -= 1;
  }
  await cart.save();
  res.json({ message: 'Quantity updated', cart: cart.items });
});

// Remove item from cart
app.post('/cart/remove', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: 'Not authenticated' });
  const { courseId } = req.body;
  if (!courseId) return res.status(400).json({ message: 'Missing courseId' });

  const cart = await Cart.findOne({ userId: req.session.userId });
  if (!cart) return res.status(404).json({ message: 'Cart not found' });

  cart.items = cart.items.filter(i => i.courseId !== courseId);
  await cart.save();
  res.json({ message: 'Item removed', cart: cart.items });
});

// Add to wishlist
app.post('/wishlist/add', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: 'Not authenticated' });
  const { courseId, title, price, duration, imageUrl } = req.body; // Add imageUrl
  if (!courseId) return res.status(400).json({ message: 'Missing courseId' });

  let wishlist = await Wishlist.findOne({ userId: req.session.userId });
  if (!wishlist) {
    wishlist = new Wishlist({ userId: req.session.userId, items: [] });
  }
  // Prevent duplicates
  if (!wishlist.items.some(item => item.courseId === courseId)) {
    wishlist.items.push({ courseId, title, price, duration, imageUrl });
    await wishlist.save();
  }
  res.json({ message: 'Added to wishlist', wishlist: wishlist.items });
});

// Get wishlist
app.get('/wishlist', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: 'Not authenticated' });
  const wishlist = await Wishlist.findOne({ userId: req.session.userId });
  res.json({ wishlist: wishlist ? wishlist.items : [] });
});

// Remove from wishlist
app.post('/wishlist/remove', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ message: 'Not authenticated' });
  const { courseId } = req.body;
  if (!courseId) return res.status(400).json({ message: 'Missing courseId' });

  const wishlist = await Wishlist.findOne({ userId: req.session.userId });
  if (!wishlist) return res.status(404).json({ message: 'Wishlist not found' });

  wishlist.items = wishlist.items.filter(i => i.courseId !== courseId);
  await wishlist.save();
  res.json({ message: 'Item removed', wishlist: wishlist.items });
});

// Job application endpoint
app.post('/apply-trainer', (req, res, next) => {
  try {
    const uploadAzure = makeUpload(cfg.azure?.resumeContainer || 'resumes').single('resume');
    uploadAzure(req, res, next);
  } catch (e) {
    console.error(e.message);
    return res.status(503).json({ message: 'File storage not configured' });
  }
}, async (req, res) => {
  try {
    const { name, email, phone, trainingCourses, trainingExperience, linkedinProfile } = req.body;
    if (!name || !email || !phone || !trainingCourses || !trainingExperience) {
      return res.status(400).json({ message: 'All required fields must be filled.' });
    }
    // Azure Blob Storage URL
    const resumeUrl = req.file ? req.file.url : '';
    const application = new TrainerApplication({
      name,
      email,
      phone,
      trainingCourses,
      trainingExperience,
      linkedinProfile,
      resumeUrl
    });
    await application.save();
    res.status(201).json({ message: 'Application submitted successfully!' });
  } catch (err) {
    console.error('Application error:', err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Upload course image
app.post('/course/image', (req, res, next) => {
  try {
    const uploadCourseImage = makeUpload(cfg.azure?.courseContainer || 'course-images').single('courseImage');
    uploadCourseImage(req, res, next);
  } catch (e) {
    console.error(e.message);
    return res.status(503).json({ message: 'File storage not configured' });
  }
}, async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No image uploaded' });
    }
    const imageUrl = req.file.url;
    res.json({ message: 'Course image uploaded successfully', imageUrl });
  } catch (err) {
    console.error('Course image upload error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Payment success endpoint
app.post('/payment/success', async (req, res) => {
  try {
    const { userId, courses, totalAmount, status, paymentDate } = req.body;
    if (!userId || !courses || !totalAmount || !status || !paymentDate) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    // Increment order counter
    let counter = await Counter.findOneAndUpdate(
      { name: 'order' },
      { $inc: { value: 1 } },
      { new: true, upsert: true }
    );

    // Create order
    const order = new Order({
      orderId: counter.value,
      userId,
      courses: courses.map(c => ({
        courseId: c.courseId,
        title: c.title,
        price: c.price
      })),
      totalAmount,
      status,
      paymentDate
    });
    await order.save();

    // Create progress entries
    const progressEntries = courses.map(c => ({
      userId,
      courseId: c.courseId,
      title: c.title,
      price: c.price,
      duration: c.duration,
      status: 'enrolled',
      enrolledAt: paymentDate
    }));
    await Progress.insertMany(progressEntries);

    res.status(201).json({ message: 'Order and progress saved' });
  } catch (err) {
    console.error('Payment success error:', err);
    res.status(500).json({ message: 'Server error' });
  }
});


// Get progress for a user
app.get('/progress', async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ message: 'Missing userId' });
  const progress = await Progress.find({ userId });
  res.json({ progress });
});

// Get orders for a user
app.get('/orders', async (req, res) => {
  const { userId } = req.query;
  if (!userId) return res.status(400).json({ message: 'Missing userId' });
  const orders = await Order.find({ userId }).sort({ paymentDate: -1 });
  res.json({ orders });
});

// Start HTTP immediately for Azure warmup
app.listen(PORT, '0.0.0.0', () => console.log(`HTTP listening on ${PORT}`));

// Connect to MongoDB after server start; do not exit on failure
mongoose.connect(cfg.mongodbUri, { serverSelectionTimeoutMS: 15000 })
  .then(() => {
    console.log('✅ Mongo connected');
    dbReady = true;
    app.use(session({
      secret: cfg.jwtSecret,
      resave: false,
      saveUninitialized: false,
      store: MongoStore.create({ mongoUrl: cfg.mongodbUri }),
      cookie: {
        sameSite: cfg.session?.sameSite ?? 'None',
        secure: cfg.session?.secure ?? true,
        httpOnly: cfg.session?.httpOnly ?? true,
        maxAge: cfg.session?.maxAgeMs ?? 24 * 60 * 60 * 1000
      }
    }));
  })
  .catch(err => {
    console.error('❌ Mongo connect failed (server still running):', err.message);
  });

process.on('unhandledRejection', (reason) => {
  console.error('unhandledRejection', reason);
  // keep process alive for warmup; consider restart policy outside
});
process.on('uncaughtException', (err) => {
  console.error('uncaughtException', err);
  // keep process alive for warmup; consider restart policy outside
});
app.get('/protected', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  res.json({ message: 'You are authenticated!', user: req.session });
});