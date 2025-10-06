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
const crypto = require('crypto');
const { SESClient, SendEmailCommand } = require('@aws-sdk/client-ses');
const cron = require('node-cron');
const TrainerApplication = require('./TrainerApplication');
const Order = require('./Order');
const Progress = require('./Progress');
const BrochureRequest = require('./BrochureRequest');
const VoucherRequest = require('./VoucherRequest');
const InstagramPost = require('./Instagram');
const FacebookPost = require('./FacebookPost');
const TwitterPost = require('./TwitterPost');
const YouTubeVideo = require('./YouTubeVideo');
const ContactForm = require('./ContactForm');
const Newsletter = require('./Newsletter');

const app = express();
app.set('trust proxy', 1);
const cfg = getConfig();
const PORT = process.env.PORT || 8080;
let dbReady = false;
// AWS SES client (lazy init per config)
let sesClient = null;
function getSesClient() {
  if (!sesClient) {
    if (!cfg.aws?.accessKeyId || !cfg.aws?.secretAccessKey || !cfg.aws?.sesRegion || !cfg.aws?.sesFromEmail) {
      console.warn('AWS SES not fully configured');
      return null;
    }
    sesClient = new SESClient({
      region: cfg.aws.sesRegion,
      credentials: {
        accessKeyId: cfg.aws.accessKeyId,
        secretAccessKey: cfg.aws.secretAccessKey
      }
    });
  }
  return sesClient;
}

async function sendVerificationEmail(toEmail, token) {
  const client = getSesClient();
  if (!client) throw new Error('Email service not configured');
  const verifyUrl = `${cfg.frontendBaseUrl}/verify-email?token=${token}`;
  const params = {
    Source: cfg.aws.sesFromEmail,
    Destination: { ToAddresses: [toEmail] },
    Message: {
      Subject: { Data: 'Verify your email' },
      Body: {
        Text: { Data: `Welcome to Gisul!\n\nPlease verify your email by clicking the link below within 24 hours:\n\n${verifyUrl}\n\nIf you did not sign up, you can ignore this email.` }
      }
    }
  };
  await client.send(new SendEmailCommand(params));
}

function generateVerificationToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Password reset email via AWS SES
async function sendPasswordResetEmail(toEmail, token) {
  const client = getSesClient();
  if (!client) throw new Error('Email service not configured');
  const resetUrl = `${cfg.frontendBaseUrl}/reset-password?token=${token}`;
  const html = `
    <div style="font-family:Arial,sans-serif;line-height:1.6;color:#222">
      <h2 style="color:#111;margin-bottom:16px">Password Reset Request - Gisul</h2>
      <p>We received a request to reset your password. Click the button below to set a new password. This link is valid for 1 hour.</p>
      <p style="margin:24px 0">
        <a href="${resetUrl}" style="background:#0d6efd;color:#fff;text-decoration:none;padding:12px 20px;border-radius:6px;display:inline-block">Reset Password</a>
      </p>
      <p>If the button doesn't work, copy and paste this link into your browser:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
      <hr style="border:none;border-top:1px solid #eee;margin:24px 0"/>
      <p style="font-size:13px;color:#555">If you did not request a password reset, you can safely ignore this email. The link will expire in 1 hour.</p>
    </div>
  `;
  const text = `Password Reset Request - Gisul\n\n` +
    `We received a request to reset your password. Use the link below within 1 hour:\n${resetUrl}\n\n` +
    `If you did not request this, you can ignore this email.`;
  const params = {
    Source: cfg.aws.sesFromEmail,
    Destination: { ToAddresses: [toEmail] },
    Message: {
      Subject: { Data: 'Password Reset Request - Gisul' },
      Body: {
        Text: { Data: text },
        Html: { Data: html }
      }
    }
  };
  await client.send(new SendEmailCommand(params));
}

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
  '/signup',
  '/forgot-password','/reset-password','/verify-reset-token'
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

    // Only allow Gmail emails
    const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
    if (!gmailRegex.test(email || '')) {
      return res.status(400).json({ message: 'Only Gmail addresses are allowed.' });
    }

    // Basic validation for manual signup
    if (!email || !username || !phone || !password) {
      return res.status(400).json({ message: 'All fields are required.' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      if (!existingUser.isEmailVerified) {
        // resend verification
        try {
          const token = generateVerificationToken();
          existingUser.emailVerificationToken = token;
          existingUser.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
          await existingUser.save();
          await sendVerificationEmail(existingUser.email, token);
        } catch (e) {
          console.error('Resend verification on signup failed:', e);
        }
        return res.status(409).json({ message: 'Account exists but not verified. Verification email resent if possible.' });
      }
      return res.status(409).json({ message: 'Email or username already in use.' });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new unverified user
    const token = generateVerificationToken();
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    const newUser = new User({
      email,
      username,
      phone,
      password: hashedPassword,
      isEmailVerified: false,
      emailVerificationToken: token,
      emailVerificationExpires: expires
    });

    await newUser.save();

    try {
      await sendVerificationEmail(email, token);
    } catch (emailErr) {
      // Cleanup user if email sending fails
      await User.deleteOne({ _id: newUser._id });
      console.error('Verification email send failed:', emailErr);
      return res.status(502).json({ message: 'Failed to send verification email. Please try again later.' });
    }

    res.status(201).json({ message: 'User registered. Check your email to verify your account.' });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

app.use(session({
  secret: cfg.jwtSecret,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({ 
    mongoUrl: cfg.mongodbUri,
    touchAfter: 24 * 3600
  }),
  cookie: {
    sameSite: cfg.session?.sameSite ?? 'None',
    secure: cfg.session?.secure ?? true,
    httpOnly: cfg.session?.httpOnly ?? true,
    maxAge: cfg.session?.maxAgeMs ?? 24 * 60 * 60 * 1000
  }
}));

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

    if (!user.isEmailVerified) {
      return res.status(403).json({ message: 'Email not verified. Please verify your email.' });
    }

    // Create JWT token
    const token = jwt.sign(
      { userId: user._id, email: user.email, username: user.username, isEmailVerified: user.isEmailVerified },
      cfg.jwtSecret,
      { expiresIn: '1h' }
    );

    // Set session
    req.session.userId = user._id;
    req.session.username = user.username;
    req.session.email = user.email;
    req.session.isEmailVerified = user.isEmailVerified;

    res.status(200).json({ message: 'Login successful!', token, session: req.session });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Server error. Please try again later.' });
  }
});

// Email verification endpoints
app.get('/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;
    if (!token) return res.status(400).json({ message: 'Missing token' });
    const user = await User.findOne({ emailVerificationToken: token });
    if (!user) return res.status(400).json({ message: 'Invalid verification token' });
    if (!user.emailVerificationExpires || user.emailVerificationExpires < new Date()) {
      return res.status(400).json({ message: 'Verification token expired' });
    }
    user.isEmailVerified = true;
    user.emailVerifiedAt = new Date();
    user.emailVerificationToken = undefined;
    user.emailVerificationExpires = undefined;
    await user.save();
    const base = cfg.frontendBaseUrl || 'https://gisul.co.in';
    return res.redirect(`${base}/verification-success`);
  } catch (err) {
    console.error('Verify email error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

app.post('/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });
    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.isEmailVerified) return res.status(400).json({ message: 'Email already verified' });

    const token = generateVerificationToken();
    user.emailVerificationToken = token;
    user.emailVerificationExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await user.save();
    await sendVerificationEmail(email, token);
    return res.json({ message: 'Verification email resent' });
  } catch (err) {
    console.error('Resend verification error:', err);
    return res.status(500).json({ message: 'Server error' });
  }
});

// Forgot Password - rate limiter 3 per hour
const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many password reset attempts. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// POST /forgot-password
app.post('/forgot-password', forgotPasswordLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, message: 'Valid email is required.' });
    }

    // Normalize email and find user (case-insensitive)
    const normalized = String(email).trim().toLowerCase();
    const user = await User.findOne({ email: normalized });

    // If no user, return generic success to prevent enumeration
    if (!user) {
      return res.status(200).json({ success: true, message: 'Password reset instructions have been sent to your email.' });
    }

    // Prevent for OAuth-only accounts
    if (!user.password && user.oauthProvider) {
      return res.status(400).json({ success: false, message: 'This account uses OAuth login. Use Google sign-in.' });
    }

    // Generate token and store hashed
    const token = crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(token).digest('hex');
    user.passwordResetToken = hashed;
    user.passwordResetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    await user.save();

    try {
      await sendPasswordResetEmail(user.email, token);
    } catch (emailErr) {
      // Cleanup on failure
      user.passwordResetToken = undefined;
      user.passwordResetExpires = undefined;
      await user.save();
      console.error('Password reset email send failed:', emailErr);
      return res.status(502).json({ success: false, message: 'Failed to send reset email. Please try again later.' });
    }

    return res.status(200).json({ success: true, message: 'Password reset instructions have been sent to your email.' });
  } catch (err) {
    console.error('Forgot password error:', err);
    return res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
  }
});

// GET /verify-reset-token/:token
app.get('/verify-reset-token/:token', async (req, res) => {
  try {
    const { token } = req.params;
    if (!token) return res.status(400).json({ success: false, message: 'Missing token' });
    const hashed = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ passwordResetToken: hashed, passwordResetExpires: { $gt: new Date() } });
    if (!user) return res.status(400).json({ success: false, message: 'Invalid or expired token' });
    return res.json({ success: true, email: user.email });
  } catch (err) {
    console.error('Verify reset token error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// POST /reset-password
app.post('/reset-password', async (req, res) => {
  try {
    const { token, newPassword, confirmPassword } = req.body || {};
    if (!token || !newPassword || !confirmPassword) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).json({ success: false, message: 'Passwords do not match.' });
    }
    if (String(newPassword).length < 8) {
      return res.status(400).json({ success: false, message: 'Password must be at least 8 characters.' });
    }

    const hashed = crypto.createHash('sha256').update(token).digest('hex');
    const user = await User.findOne({ passwordResetToken: hashed, passwordResetExpires: { $gt: new Date() } });
    if (!user) return res.status(400).json({ success: false, message: 'Invalid or expired token.' });

    const hashedPassword = await bcrypt.hash(String(newPassword), 10);
    user.password = hashedPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    return res.json({ success: true, message: 'Password has been reset successfully.' });
  } catch (err) {
    console.error('Reset password error:', err);
    return res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
  }
});
// Middleware to require verified email for protected operations
function requireEmailVerification(req, res, next) {
  if (!req.session?.isEmailVerified) {
    return res.status(403).json({ message: 'Email verification required' });
  }
  next();
}

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
      profilePic: user.profilePic || '',
      isEmailVerified: !!user.isEmailVerified
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
app.post('/cart/add', requireEmailVerification, async (req, res) => {
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

// ---- Upload constraints for resumes: PDF only, max 5MB ----
const pdfOnly = (req, file, cb) => {
  if (file.mimetype === 'application/pdf') return cb(null, true);
  const e = new Error('Only PDF resumes are allowed');
  e.status = 400;
  cb(e);
};

function makeAzureStorageForResumes(containerName) {
  if (!cfg.azure?.storageConnectionString) {
    const e = new Error('Azure Storage not configured');
    e.status = 503;
    throw e;
  }
  return new MulterAzureStorage({
    connectionString: cfg.azure.storageConnectionString,
    containerName,
    blobName: (_req, file) => Date.now() + '-' + file.originalname,
    contentSettings: { contentType: (_req, file) => file.mimetype }
  });
}

const makeResumeUpload = (container) => multer({
  storage: makeAzureStorageForResumes(container),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: pdfOnly
});

// Job application endpoint (PDF only, 5MB)
app.post(
  '/apply-trainer',
  (req, res, next) => {
    try {
      const uploadAzure = makeResumeUpload(cfg.azure?.resumeContainer || 'resumes').single('resume'); // field name: 'resume'
      uploadAzure(req, res, next);
    } catch (e) {
      return next(e);
    }
  },
  async (req, res, next) => {
    try {
      const { name, email, phone, trainingCourses, trainingExperience, linkedinProfile } = req.body;

      if (!name || !email || !phone || !trainingCourses || !trainingExperience) {
        return res.status(400).json({ message: 'All required fields must be filled.' });
      }
      if (!req.file) {
        return res.status(400).json({ message: 'Resume file missing' });
      }
      if (!req.file.url) {
        return res.status(400).json({ message: 'Resume upload failed' });
      }

      const application = new TrainerApplication({
        name,
        email,
        phone,
        trainingCourses,
        trainingExperience,
        linkedinProfile,
        resumeUrl: req.file.url
      });

      await application.save();
      return res.status(201).json({ message: 'Application submitted successfully!' });
    } catch (err) {
      return next(err);
    }
  }
);

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
app.post('/payment/success', requireEmailVerification, async (req, res) => {
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

// Move protected route above global error handler/listen to ensure handler catches errors
app.get('/protected', (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ message: 'Unauthorized' });
  }
  res.json({ message: 'You are authenticated!', user: req.session });
});

// ===== CONTACT FORM, NEWSLETTER, BROCHURE & VOUCHER ENDPOINTS =====

// Rate limiters for contact form and newsletter
const contactFormLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 requests per 15 minutes per IP
  message: { success: false, message: 'Too many contact form submissions. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const newsletterLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 requests per hour per IP
  message: { success: false, message: 'Too many newsletter requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Brochure & Voucher: rate limit 3 per 15 minutes
const formLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { success: false, message: 'Too many requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Email validation helpers
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

const isGmailEmail = (email) => {
  const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/;
  return gmailRegex.test(email);
};

// Simple phone number validation: allows +, digits, spaces, hyphens, parentheses, 7-20 chars
const isValidPhone = (phone) => {
  const phoneRegex = /^[+]?[(]?[0-9]{1,4}[)]?[0-9\s\-]{5,}$/;
  const normalized = String(phone || '').trim();
  return normalized.length >= 7 && normalized.length <= 20 && phoneRegex.test(normalized);
};

// POST /contact - Contact form submission
app.post('/contact', contactFormLimiter, async (req, res) => {
  try {
    const { name, email, comment } = req.body;

    // Validation
    if (!name || !email || !comment) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name, email, and comment are required.' 
      });
    }

    // Email format validation
    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please provide a valid email address.' 
      });
    }

    // Name length validation
    if (name.trim().length < 2 || name.trim().length > 100) {
      return res.status(400).json({ 
        success: false, 
        message: 'Name must be between 2 and 100 characters.' 
      });
    }

    // Comment length validation
    if (comment.trim().length < 10 || comment.trim().length > 1000) {
      return res.status(400).json({ 
        success: false, 
        message: 'Comment must be between 10 and 1000 characters.' 
      });
    }

    // Create contact form entry
    const contactForm = new ContactForm({
      name: name.trim(),
      email: email.trim().toLowerCase(),
      comment: comment.trim()
    });

    await contactForm.save();

    res.status(201).json({ 
      success: true, 
      message: 'Thank you for your message! We will get back to you soon.' 
    });

  } catch (err) {
    console.error('Contact form error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error. Please try again later.' 
    });
  }
});

// POST /newsletter/subscribe - Newsletter subscription
app.post('/newsletter/subscribe', newsletterLimiter, async (req, res) => {
  try {
    const { email } = req.body;

    // Validation
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required.' 
      });
    }

    // Gmail-only validation
    if (!isGmailEmail(email)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Only Gmail addresses are allowed for newsletter subscription.' 
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check for existing subscription
    const existingSubscription = await Newsletter.findOne({ email: normalizedEmail });

    if (existingSubscription) {
      if (existingSubscription.isActive) {
        return res.status(409).json({ 
          success: false, 
          message: 'This email is already subscribed to our newsletter.' 
        });
      } else {
        // Reactivate existing subscription
        existingSubscription.isActive = true;
        existingSubscription.subscribedAt = new Date();
        await existingSubscription.save();
        
        return res.status(200).json({ 
          success: true, 
          message: 'Welcome back! Your newsletter subscription has been reactivated.' 
        });
      }
    }

    // Create new subscription
    const newsletter = new Newsletter({
      email: normalizedEmail
    });

    await newsletter.save();

    res.status(201).json({ 
      success: true, 
      message: 'Successfully subscribed to our newsletter! Thank you for joining us.' 
    });

  } catch (err) {
    console.error('Newsletter subscription error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error. Please try again later.' 
    });
  }
});

// POST /newsletter/unsubscribe - Newsletter unsubscription
app.post('/newsletter/unsubscribe', async (req, res) => {
  try {
    const { email } = req.body;

    // Validation
    if (!email) {
      return res.status(400).json({ 
        success: false, 
        message: 'Email is required.' 
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Find and deactivate subscription
    const subscription = await Newsletter.findOne({ email: normalizedEmail });

    if (!subscription) {
      return res.status(404).json({ 
        success: false, 
        message: 'Email not found in our newsletter list.' 
      });
    }

    if (!subscription.isActive) {
      return res.status(400).json({ 
        success: false, 
        message: 'This email is already unsubscribed.' 
      });
    }

    // Soft delete (set isActive to false)
    subscription.isActive = false;
    await subscription.save();

    res.status(200).json({ 
      success: true, 
      message: 'Successfully unsubscribed from our newsletter. We\'re sorry to see you go!' 
    });

  } catch (err) {
    console.error('Newsletter unsubscription error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error. Please try again later.' 
    });
  }
});

// ===== INSTAGRAM INTEGRATION (Graph API) =====

// Build Instagram API helpers
const getInstagramPosts = async () => {
  try {
    const accountId = cfg.instagram?.businessAccountId;
    const accessToken = cfg.instagram?.accessToken;
    if (!accountId || !accessToken) {
      console.warn('Instagram env vars missing: INSTAGRAM_BUSINESS_ACCOUNT_ID or INSTAGRAM_ACCESS_TOKEN');
      return [];
    }

    const fields = [
      'id','caption','media_type','media_url','permalink','timestamp','like_count','comments_count','thumbnail_url',
      'children{media_type,media_url}'
    ].join(',');

    const url = `https://graph.facebook.com/v21.0/${accountId}/media`;
    const params = new URLSearchParams({ fields, access_token: accessToken, limit: '25' });
    const resp = await axios.get(`${url}?${params.toString()}`);
    const data = Array.isArray(resp?.data?.data) ? resp.data.data : [];
    return data;
  } catch (err) {
    console.error('Instagram getInstagramPosts error:', err?.response?.data || err.message);
    return [];
  }
};

const syncInstagramPosts = async () => {
  try {
    const posts = await getInstagramPosts();
    if (!Array.isArray(posts) || posts.length === 0) return 0;
    let upserted = 0;
    for (const p of posts) {
      const children = Array.isArray(p?.children?.data)
        ? p.children.data.map(c => ({ mediaType: c.media_type, mediaUrl: c.media_url }))
        : [];
      const update = {
        postId: p.id,
        caption: p.caption || '',
        mediaType: p.media_type,
        mediaUrl: p.media_url || '',
        permalink: p.permalink || '',
        timestamp: p.timestamp ? new Date(p.timestamp) : undefined,
        likeCount: typeof p.like_count === 'number' ? p.like_count : 0,
        commentsCount: typeof p.comments_count === 'number' ? p.comments_count : 0,
        thumbnail: p.thumbnail_url || '',
        children
      };
      const res = await InstagramPost.findOneAndUpdate(
        { postId: p.id },
        { $set: update },
        { upsert: true, new: true }
      );
      if (res) upserted += 1;
    }
    console.log(`📸 Instagram sync complete. Upserted ${upserted} posts.`);
    return upserted;
  } catch (err) {
    console.error('Instagram syncInstagramPosts error:', err.message);
    return 0;
  }
};

// ===== FACEBOOK INTEGRATION (Graph API) =====

// Improved Facebook API helper with better error handling
const getFacebookPosts = async () => {
  const pageId = cfg.facebook?.pageId;
  const accessToken = cfg.facebook?.pageAccessToken;
  
  if (!pageId || !accessToken) {
    throw new Error('Facebook credentials not configured: FACEBOOK_PAGE_ID or FACEBOOK_PAGE_ACCESS_TOKEN missing');
  }

  try {
    const fields = [
      'id','message','story','full_picture','permalink_url','created_time','type',
      'likes.summary(true)','comments.summary(true)','shares'
    ].join(',');

    const url = `https://graph.facebook.com/v21.0/${pageId}/posts`;
    const params = new URLSearchParams({ fields, access_token: accessToken, limit: '25' });
    const resp = await axios.get(`${url}?${params.toString()}`);
    const data = Array.isArray(resp?.data?.data) ? resp.data.data : [];
    return data;
  } catch (err) {
    // Specific error handling
    if (err?.response?.status === 401) {
      console.error('Facebook API: Token expired or invalid');
    } else if (err?.response?.status === 429) {
      console.error('Facebook API: Rate limit exceeded');
    } else if (err?.response?.status === 400) {
      console.error('Facebook API: Bad request - check configuration');
    }
    console.error('Facebook getFacebookPosts error:', err?.response?.data || err.message);
    throw err; // Propagate error instead of silent failure
  }
};

// ===== TWITTER INTEGRATION (API v2) =====

// Fetch tweets for a user
const getTwitterTweets = async () => {
  try {
    const bearer = cfg.twitter?.bearerToken;
    const userId = cfg.twitter?.userId;
    if (!bearer || !userId) {
      console.warn('Twitter env vars missing: TWITTER_BEARER_TOKEN or TWITTER_USER_ID');
      return [];
    }

    const url = `https://api.twitter.com/2/users/${userId}/tweets`;
    const params = new URLSearchParams({
      max_results: '20',
      expansions: 'attachments.media_keys,entities.mentions.username',
      'tweet.fields': 'created_at,entities,public_metrics',
      'media.fields': 'media_key,type,url,preview_image_url'
    });
    const resp = await axios.get(`${url}?${params.toString()}`, {
      headers: { Authorization: `Bearer ${bearer}` }
    });

    const tweets = Array.isArray(resp?.data?.data) ? resp.data.data : [];
    const includes = resp?.data?.includes || {};
    const mediaMap = new Map();
    if (Array.isArray(includes.media)) {
      for (const m of includes.media) mediaMap.set(m.media_key, m);
    }

    // Attach resolved media array per tweet
    const enriched = tweets.map(t => {
      const mediaKeys = t?.attachments?.media_keys || [];
      const media = mediaKeys.map(k => mediaMap.get(k)).filter(Boolean).map(m => ({
        mediaKey: m.media_key,
        type: m.type,
        url: m.url || '',
        previewImageUrl: m.preview_image_url || ''
      }));
      return { ...t, _mediaResolved: media };
    });
    return enriched;
  } catch (err) {
    console.error('Twitter getTwitterTweets error:', err?.response?.data || err.message);
    return [];
  }
};

const syncTwitterTweets = async () => {
  try {
    const tweets = await getTwitterTweets();
    if (!Array.isArray(tweets) || tweets.length === 0) return 0;
    let upserted = 0;
    for (const t of tweets) {
      const entities = t.entities || {};
      const hashtags = Array.isArray(entities.hashtags) ? entities.hashtags.map(h => h.tag) : [];
      const mentions = Array.isArray(entities.mentions) ? entities.mentions.map(m => m.username) : [];
      const metrics = t.public_metrics || {};
      const update = {
        tweetId: t.id,
        text: t.text || '',
        createdTime: t.created_at ? new Date(t.created_at) : undefined,
        likeCount: metrics.like_count || 0,
        retweetCount: metrics.retweet_count || 0,
        replyCount: metrics.reply_count || 0,
        quoteCount: metrics.quote_count || 0,
        media: Array.isArray(t._mediaResolved) ? t._mediaResolved : [],
        hashtags,
        mentions,
        permalink: `https://twitter.com/i/web/status/${t.id}`
      };
      const res = await TwitterPost.findOneAndUpdate(
        { tweetId: t.id },
        { $set: update },
        { upsert: true, new: true }
      );
      if (res) upserted += 1;
    }
    console.log(`🐦 Twitter sync complete. Upserted ${upserted} tweets.`);
    return upserted;
  } catch (err) {
    console.error('Twitter syncTwitterTweets error:', err.message);
    return 0;
  }
};

// ===== YOUTUBE INTEGRATION (Data API v3) =====

// Fetch videos from YouTube channel
const getYouTubeVideos = async () => {
  try {
    const apiKey = cfg.youtube?.apiKey;
    const channelId = cfg.youtube?.channelId;
    
    if (!apiKey || !channelId) {
      console.warn('YouTube env vars missing: YOUTUBE_API_KEY or YOUTUBE_CHANNEL_ID');
      return [];
    }

    // Step 1: Get channel's uploads playlist ID
    const channelUrl = 'https://www.googleapis.com/youtube/v3/channels';
    const channelParams = new URLSearchParams({
      part: 'contentDetails',
      id: channelId,
      key: apiKey
    });
    
    const channelResp = await axios.get(`${channelUrl}?${channelParams.toString()}`);
    const uploadsPlaylistId = channelResp?.data?.items?.[0]?.contentDetails?.relatedPlaylists?.uploads;
    
    if (!uploadsPlaylistId) {
      console.error('YouTube: Could not find uploads playlist for channel:', channelId);
      return [];
    }

    // Step 2: Get videos from uploads playlist
    const playlistUrl = 'https://www.googleapis.com/youtube/v3/playlistItems';
    const playlistParams = new URLSearchParams({
      part: 'snippet,contentDetails',
      playlistId: uploadsPlaylistId,
      maxResults: '50',
      key: apiKey
    });
    
    const playlistResp = await axios.get(`${playlistUrl}?${playlistParams.toString()}`);
    const playlistItems = Array.isArray(playlistResp?.data?.items) ? playlistResp.data.items : [];
    
    if (playlistItems.length === 0) {
      console.log('YouTube: No videos found in uploads playlist');
      return [];
    }

    // Step 3: Get detailed video information and statistics
    const videoIds = playlistItems.map(item => item.snippet.resourceId.videoId).join(',');
    const videosUrl = 'https://www.googleapis.com/youtube/v3/videos';
    const videosParams = new URLSearchParams({
      part: 'snippet,statistics,contentDetails,player',
      id: videoIds,
      key: apiKey
    });
    
    const videosResp = await axios.get(`${videosUrl}?${videosParams.toString()}`);
    const videos = Array.isArray(videosResp?.data?.items) ? videosResp.data.items : [];
    
    return videos;
  } catch (err) {
    // Handle specific YouTube API errors
    if (err?.response?.status === 403) {
      console.error('YouTube API: Quota exceeded or API key invalid');
    } else if (err?.response?.status === 400) {
      console.error('YouTube API: Bad request - check channel ID and API key');
    } else if (err?.response?.status === 404) {
      console.error('YouTube API: Channel not found');
    }
    console.error('YouTube getYouTubeVideos error:', err?.response?.data || err.message);
    return [];
  }
};

const syncYouTubeVideos = async () => {
  try {
    const videos = await getYouTubeVideos();
    if (!Array.isArray(videos) || videos.length === 0) {
      console.log('📺 YouTube sync: No videos returned from API');
      return 0;
    }
    
    let upserted = 0;
    let errors = 0;
    
    for (const video of videos) {
      try {
        // Extract video data
        const snippet = video.snippet || {};
        const statistics = video.statistics || {};
        const contentDetails = video.contentDetails || {};
        const player = video.player || {};
        
        const update = {
          videoId: video.id,
          title: snippet.title || '',
          description: snippet.description || '',
          thumbnailUrl: snippet.thumbnails?.default?.url || '',
          thumbnailHdUrl: snippet.thumbnails?.high?.url || snippet.thumbnails?.maxres?.url || '',
          publishedAt: snippet.publishedAt ? new Date(snippet.publishedAt) : new Date(),
          duration: contentDetails.duration || '',
          viewCount: parseInt(statistics.viewCount || '0', 10),
          likeCount: parseInt(statistics.likeCount || '0', 10),
          commentCount: parseInt(statistics.commentCount || '0', 10),
          tags: Array.isArray(snippet.tags) ? snippet.tags : [],
          categoryId: snippet.categoryId || '',
          channelTitle: snippet.channelTitle || '',
          embedHtml: player.embedHtml || '',
          updatedAt: new Date()
        };
        
        const res = await YouTubeVideo.findOneAndUpdate(
          { videoId: video.id },
          { $set: update },
          { upsert: true, new: true, runValidators: true }
        );
        
        if (res) upserted++;
      } catch (dbErr) {
        console.error(`YouTube: Failed to upsert video ${video.id}:`, dbErr.message);
        errors++;
      }
    }
    
    console.log(`📺 YouTube sync complete. Upserted: ${upserted}, Errors: ${errors}, Total fetched: ${videos.length}`);
    return upserted;
  } catch (err) {
    console.error('YouTube syncYouTubeVideos error:', err.message);
    throw err; // Propagate error for cron job awareness
  }
};

const syncFacebookPosts = async () => {
  try {
    const posts = await getFacebookPosts();
    if (!Array.isArray(posts) || posts.length === 0) {
      console.log('📘 Facebook sync: No posts returned from API');
      return 0;
    }
    
    let upserted = 0;
    let errors = 0;
    const validTypes = ['link', 'status', 'photo', 'video', 'offer', 'event', 'note', 'other'];
    
    for (const p of posts) {
      // Skip posts without required fields
      if (!p.id || !p.created_time) {
        console.warn(`Facebook: Skipping post missing required fields (id: ${p.id || 'unknown'})`);
        errors++;
        continue;
      }
      
      // Normalize type to match schema enum
      let postType = p.type || 'other';
      if (!validTypes.includes(postType)) {
        console.warn(`Facebook: Unknown post type "${postType}" for post ${p.id}, defaulting to "other"`);
        postType = 'other';
      }
      
      const update = {
        postId: p.id,
        message: p.message || '',
        story: p.story || '',
        fullPicture: p.full_picture || '',
        permalink: p.permalink_url || '',
        createdTime: new Date(p.created_time), // Always create valid Date
        type: postType,
        likes: Math.max(0, p.likes?.summary?.total_count || 0),
        comments: Math.max(0, p.comments?.summary?.total_count || 0),
        shares: Math.max(0, p.shares?.count || 0),
        updatedAt: new Date()
      };
      
      try {
        const res = await FacebookPost.findOneAndUpdate(
          { postId: p.id },
          { $set: update },
          { upsert: true, new: true, runValidators: true }
        );
        if (res) upserted++;
      } catch (dbErr) {
        console.error(`Facebook: Failed to upsert post ${p.id}:`, dbErr.message);
        errors++;
      }
    }
    
    console.log(`📘 Facebook sync complete. Upserted: ${upserted}, Errors: ${errors}, Total fetched: ${posts.length}`);
    return upserted;
  } catch (err) {
    console.error('Facebook syncFacebookPosts error:', err.message);
    throw err; // Propagate error for cron job awareness
  }
};

// Public endpoint: GET /api/instagram/posts
app.get('/api/instagram/posts', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '12')));
    const skip = (page - 1) * limit;
    const query = {};

    const total = await InstagramPost.countDocuments(query);
    const posts = await InstagramPost.find(query)
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit)
      .select('-__v');

    return res.json({
      success: true,
      data: posts,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('GET /api/instagram/posts error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Manual sync: POST /api/instagram/sync
app.post('/api/instagram/sync', async (_req, res) => {
  try {
    const count = await syncInstagramPosts();
    return res.json({ success: true, message: `Synced ${count} posts` });
  } catch (err) {
    console.error('POST /api/instagram/sync error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Refresh long-lived token: POST /api/instagram/refresh-token
app.post('/api/instagram/refresh-token', async (req, res) => {
  try {
    const appId = cfg.facebook?.appId;
    const appSecret = process.env.FACEBOOK_APP_SECRET; // Direct env access for token refresh only
    const fbExchangeToken = cfg.instagram?.accessToken;
    if (!appId || !appSecret || !fbExchangeToken) {
      return res.status(400).json({ success: false, message: 'Missing Facebook app credentials or access token' });
    }

    const url = 'https://graph.facebook.com/v21.0/oauth/access_token';
    const params = new URLSearchParams({
      grant_type: 'fb_exchange_token',
      client_id: appId,
      client_secret: appSecret,
      fb_exchange_token: fbExchangeToken
    });
    const resp = await axios.get(`${url}?${params.toString()}`);
    const { access_token, token_type, expires_in } = resp.data || {};
    if (!access_token) {
      return res.status(502).json({ success: false, message: 'Failed to refresh token' });
    }
    return res.json({ success: true, token: access_token, tokenType: token_type, expiresIn: expires_in });
  } catch (err) {
    console.error('POST /api/instagram/refresh-token error:', err?.response?.data || err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ===== FACEBOOK API ENDPOINTS =====

// Public endpoint: GET /api/facebook/posts
app.get('/api/facebook/posts', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '12')));
    const skip = (page - 1) * limit;
    const query = {};

    const total = await FacebookPost.countDocuments(query);
    const posts = await FacebookPost.find(query)
      .sort({ createdTime: -1 })
      .skip(skip)
      .limit(limit)
      .select('-__v');

    return res.json({
      success: true,
      data: posts,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('GET /api/facebook/posts error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});
app.post('/api/facebook/refresh-token', async (req, res) => {
  try {
    const appId = cfg.facebook?.appId;
    const appSecret = process.env.FACEBOOK_APP_SECRET;
    const currentToken = cfg.facebook?.pageAccessToken;
    
    if (!appId || !appSecret || !currentToken) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing Facebook app credentials or page access token' 
      });
    }

    const url = 'https://graph.facebook.com/v21.0/oauth/access_token';
    const params = new URLSearchParams({
      grant_type: 'fb_exchange_token',
      client_id: appId,
      client_secret: appSecret,
      fb_exchange_token: currentToken
    });
    
    const resp = await axios.get(`${url}?${params.toString()}`);
    const { access_token, token_type, expires_in } = resp.data || {};
    
    if (!access_token) {
      return res.status(502).json({ 
        success: false, 
        message: 'Failed to refresh Facebook token' 
      });
    }
    
    return res.json({ 
      success: true, 
      token: access_token, 
      tokenType: token_type, 
      expiresIn: expires_in 
    });
  } catch (err) {
    console.error('Facebook token refresh error:', err?.response?.data || err.message);
    return res.status(500).json({ 
      success: false, 
      message: 'Server error during token refresh' 
    });
  }
});

// Manual sync: POST /api/facebook/sync
app.post('/api/facebook/sync', async (_req, res) => {
  try {
    const count = await syncFacebookPosts();
    return res.json({ success: true, message: `Synced ${count} posts` });
  } catch (err) {
    console.error('POST /api/facebook/sync error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ===== TWITTER API ENDPOINTS =====

// Public endpoint: GET /api/twitter/tweets
app.get('/api/twitter/tweets', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '12')));
    const skip = (page - 1) * limit;
    const query = {};

    const total = await TwitterPost.countDocuments(query);
    const tweets = await TwitterPost.find(query)
      .sort({ createdTime: -1 })
      .skip(skip)
      .limit(limit)
      .select('-__v');

    return res.json({
      success: true,
      data: tweets,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('GET /api/twitter/tweets error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Manual sync: POST /api/twitter/sync
app.post('/api/twitter/sync', async (_req, res) => {
  try {
    const count = await syncTwitterTweets();
    return res.json({ success: true, message: `Synced ${count} tweets` });
  } catch (err) {
    console.error('POST /api/twitter/sync error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ===== YOUTUBE API ENDPOINTS =====

// Rate limiters for YouTube endpoints
const youtubeVideosLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per 15 minutes per IP
  message: { success: false, message: 'Too many YouTube requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

const youtubeAdminLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 requests per hour per IP
  message: { success: false, message: 'Too many admin YouTube requests. Please try again later.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Public endpoint: GET /api/youtube/videos
app.get('/api/youtube/videos', youtubeVideosLimiter, async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '12')));
    const skip = (page - 1) * limit;
    const sortBy = req.query.sortBy || 'publishedAt'; // publishedAt, viewCount, likeCount
    const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
    const channel = req.query.channel;

    // Build query
    const query = {};
    if (channel) {
      query.channelTitle = new RegExp(channel, 'i');
    }

    // Build sort object
    const sort = {};
    sort[sortBy] = sortOrder;

    const total = await YouTubeVideo.countDocuments(query);
    const videos = await YouTubeVideo.find(query)
      .sort(sort)
      .skip(skip)
      .limit(limit)
      .select('-__v');

    return res.json({
      success: true,
      data: videos,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('GET /api/youtube/videos error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Public endpoint: GET /api/youtube/videos/:videoId
app.get('/api/youtube/videos/:videoId', youtubeVideosLimiter, async (req, res) => {
  try {
    const { videoId } = req.params;
    
    if (!videoId) {
      return res.status(400).json({ success: false, message: 'Video ID is required' });
    }

    const video = await YouTubeVideo.findOne({ videoId }).select('-__v');
    
    if (!video) {
      return res.status(404).json({ success: false, message: 'Video not found' });
    }

    return res.json({
      success: true,
      data: video
    });
  } catch (err) {
    console.error('GET /api/youtube/videos/:videoId error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Public endpoint: GET /api/youtube/search
app.get('/api/youtube/search', youtubeVideosLimiter, async (req, res) => {
  try {
    const { q: query } = req.query;
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '12')));
    const skip = (page - 1) * limit;

    if (!query || query.trim().length === 0) {
      return res.status(400).json({ success: false, message: 'Search query is required' });
    }

    // Search in title and description
    const searchQuery = {
      $or: [
        { title: new RegExp(query.trim(), 'i') },
        { description: new RegExp(query.trim(), 'i') },
        { tags: new RegExp(query.trim(), 'i') }
      ]
    };

    const total = await YouTubeVideo.countDocuments(searchQuery);
    const videos = await YouTubeVideo.find(searchQuery)
      .sort({ publishedAt: -1 })
      .skip(skip)
      .limit(limit)
      .select('-__v');

    return res.json({
      success: true,
      data: videos,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
      query: query.trim()
    });
  } catch (err) {
    console.error('GET /api/youtube/search error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Public endpoint: GET /api/youtube/stats
app.get('/api/youtube/stats', youtubeVideosLimiter, async (req, res) => {
  try {
    const totalVideos = await YouTubeVideo.countDocuments();
    const totalViews = await YouTubeVideo.aggregate([
      { $group: { _id: null, total: { $sum: '$viewCount' } } }
    ]);
    const totalLikes = await YouTubeVideo.aggregate([
      { $group: { _id: null, total: { $sum: '$likeCount' } } }
    ]);
    const totalComments = await YouTubeVideo.aggregate([
      { $group: { _id: null, total: { $sum: '$commentCount' } } }
    ]);
    
    // Get most popular video
    const mostPopularVideo = await YouTubeVideo.findOne({})
      .sort({ viewCount: -1 })
      .select('videoId title viewCount likeCount');

    // Get channel stats
    const channelStats = await YouTubeVideo.aggregate([
      { $group: { _id: '$channelTitle', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    return res.json({
      success: true,
      data: {
        totalVideos,
        totalViews: totalViews[0]?.total || 0,
        totalLikes: totalLikes[0]?.total || 0,
        totalComments: totalComments[0]?.total || 0,
        mostPopularVideo,
        channels: channelStats
      }
    });
  } catch (err) {
    console.error('GET /api/youtube/stats error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Admin endpoint: POST /api/youtube/sync
app.post('/api/youtube/sync', youtubeAdminLimiter, async (_req, res) => {
  try {
    const count = await syncYouTubeVideos();
    return res.json({ success: true, message: `Synced ${count} videos` });
  } catch (err) {
    console.error('POST /api/youtube/sync error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Combined endpoint: GET /api/social/posts
app.get('/api/social/posts', async (req, res) => {
  try {
    const page = Math.max(1, parseInt(req.query.page || '1'));
    const limit = Math.min(50, Math.max(1, parseInt(req.query.limit || '12')));
    const skip = (page - 1) * limit;

    // Fetch all social media posts including YouTube
    const [instagramPosts, facebookPosts, twitterPosts, youtubeVideos] = await Promise.all([
      InstagramPost.find({}).sort({ timestamp: -1 }).select('-__v'),
      FacebookPost.find({}).sort({ createdTime: -1 }).select('-__v'),
      TwitterPost.find({}).sort({ createdTime: -1 }).select('-__v'),
      YouTubeVideo.find({}).sort({ publishedAt: -1 }).select('-__v')
    ]);

    // Normalize to unified format
    const normalizedPosts = [
      ...instagramPosts.map(p => ({
        id: p.postId,
        platform: 'instagram',
        caption: p.caption || '',
        mediaUrl: p.mediaUrl || '',
        permalink: p.permalink || '',
        timestamp: p.timestamp,
        likes: p.likeCount || 0,
        comments: p.commentsCount || 0,
        type: p.mediaType || 'IMAGE',
        isVideo: p.mediaType === 'VIDEO',
        isCarousel: p.mediaType === 'CAROUSEL_ALBUM'
      })),
      ...facebookPosts.map(p => ({
        id: p.postId,
        platform: 'facebook',
        caption: p.message || p.story || '',
        mediaUrl: p.fullPicture || '',
        permalink: p.permalink || '',
        timestamp: p.createdTime,
        likes: p.likes || 0,
        comments: p.comments || 0,
        type: p.type || 'status',
        isVideo: p.type === 'video',
        isCarousel: false
      })),
      ...twitterPosts.map(t => ({
        id: t.tweetId,
        platform: 'twitter',
        caption: t.text || '',
        mediaUrl: Array.isArray(t.media) && t.media.length ? (t.media[0].url || t.media[0].previewImageUrl || '') : '',
        permalink: t.permalink || `https://twitter.com/i/web/status/${t.tweetId}`,
        timestamp: t.createdTime,
        likes: t.likeCount || 0,
        comments: t.replyCount || 0,
        type: 'tweet',
        isVideo: Array.isArray(t.media) && t.media[0]?.type === 'video',
        isCarousel: Array.isArray(t.media) && t.media.length > 1
      })),
      ...youtubeVideos.map(v => ({
        id: v.videoId,
        platform: 'youtube',
        caption: v.title || '',
        description: v.description || '',
        mediaUrl: v.thumbnailHdUrl || v.thumbnailUrl || '',
        permalink: `https://www.youtube.com/watch?v=${v.videoId}`,
        timestamp: v.publishedAt,
        likes: v.likeCount || 0,
        comments: v.commentCount || 0,
        views: v.viewCount || 0,
        duration: v.duration || '',
        channelTitle: v.channelTitle || '',
        type: 'video',
        isVideo: true,
        isCarousel: false,
        embedHtml: v.embedHtml || '',
        tags: v.tags || []
      }))
    ];

    // Sort by timestamp DESC
    normalizedPosts.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    const total = normalizedPosts.length;
    const paginatedPosts = normalizedPosts.slice(skip, skip + limit);

    return res.json({
      success: true,
      data: paginatedPosts,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) }
    });
  } catch (err) {
    console.error('GET /api/social/posts error:', err.message);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});
// POST /brochure-request - Brochure request form
app.post('/brochure-request', formLimiter, async (req, res) => {
  try {
    const { name, email, phoneNumber, city, educationQualification } = req.body;

    // Required fields
    if (!name || !email || !phoneNumber || !city || !educationQualification) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    // Validate email & phone
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }
    if (!isValidPhone(phoneNumber)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid phone number.' });
    }

    // Validate lengths
    const nameTrim = String(name).trim();
    const cityTrim = String(city).trim();
    const eduTrim = String(educationQualification).trim();
    if (nameTrim.length < 2 || nameTrim.length > 100) {
      return res.status(400).json({ success: false, message: 'Name must be between 2 and 100 characters.' });
    }
    if (cityTrim.length < 2 || cityTrim.length > 100) {
      return res.status(400).json({ success: false, message: 'City must be between 2 and 100 characters.' });
    }
    if (eduTrim.length < 2 || eduTrim.length > 200) {
      return res.status(400).json({ success: false, message: 'Education qualification must be between 2 and 200 characters.' });
    }

    const doc = new BrochureRequest({
      name: nameTrim,
      email: String(email).trim().toLowerCase(),
      phoneNumber: String(phoneNumber).trim(),
      city: cityTrim,
      educationQualification: eduTrim
    });
    await doc.save();

    return res.status(201).json({ success: true, message: 'Your brochure request has been submitted. We will contact you soon.' });
  } catch (err) {
    console.error('Brochure request error:', err);
    return res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
  }
});

// POST /voucher-request - Voucher request (enterprise watchers)
app.post('/voucher-request', formLimiter, async (req, res) => {
  try {
    const { name, email, phoneNumber, jobRole, organization, numberOfWatchers } = req.body;

    // Required fields
    if (!name || !email || !phoneNumber || !jobRole || !organization || numberOfWatchers === undefined) {
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    // Validate email & phone
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid email address.' });
    }
    if (!isValidPhone(phoneNumber)) {
      return res.status(400).json({ success: false, message: 'Please provide a valid phone number.' });
    }

    // Validate lengths
    const nameTrim = String(name).trim();
    const roleTrim = String(jobRole).trim();
    const orgTrim = String(organization).trim();
    if (nameTrim.length < 2 || nameTrim.length > 100) {
      return res.status(400).json({ success: false, message: 'Name must be between 2 and 100 characters.' });
    }
    if (roleTrim.length < 2 || roleTrim.length > 100) {
      return res.status(400).json({ success: false, message: 'Job role must be between 2 and 100 characters.' });
    }
    if (orgTrim.length < 2 || orgTrim.length > 200) {
      return res.status(400).json({ success: false, message: 'Organization must be between 2 and 200 characters.' });
    }

    // Validate numberOfWatchers
    const watchersNum = Number(numberOfWatchers);
    if (!Number.isFinite(watchersNum) || watchersNum < 1 || watchersNum > 10000) {
      return res.status(400).json({ success: false, message: 'numberOfWatchers must be a number between 1 and 10000.' });
    }

    const doc = new VoucherRequest({
      name: nameTrim,
      email: String(email).trim().toLowerCase(),
      phoneNumber: String(phoneNumber).trim(),
      jobRole: roleTrim,
      organization: orgTrim,
      numberOfWatchers: watchersNum
    });
    await doc.save();

    return res.status(201).json({ success: true, message: 'Your voucher request has been submitted. Our team will reach out shortly.' });
  } catch (err) {
    console.error('Voucher request error:', err);
    return res.status(500).json({ success: false, message: 'Server error. Please try again later.' });
  }
});
// GET /admin/contact-forms - Admin endpoint for contact form submissions
app.get('/admin/contact-forms', async (req, res) => {
  try {
    const { status, page = 1, limit = 10 } = req.query;
    
    // Build query
    const query = {};
    if (status && ['new', 'read', 'responded'].includes(status)) {
      query.status = status;
    }

    // Pagination
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(50, Math.max(1, parseInt(limit))); // Max 50 per page
    const skip = (pageNum - 1) * limitNum;

    // Get total count
    const total = await ContactForm.countDocuments(query);

    // Get paginated results
    const contactForms = await ContactForm.find(query)
      .sort({ submittedAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .select('-__v');

    res.status(200).json({
      success: true,
      data: contactForms,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum)
      }
    });

  } catch (err) {
    console.error('Admin contact forms error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error. Please try again later.' 
    });
  }
});

// GET /admin/newsletter-subscribers - Admin endpoint for newsletter subscribers
app.get('/admin/newsletter-subscribers', async (req, res) => {
  try {
    const { isActive, page = 1, limit = 10 } = req.query;
    
    // Build query
    const query = {};
    if (isActive !== undefined) {
      query.isActive = isActive === 'true';
    }

    // Pagination
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(50, Math.max(1, parseInt(limit))); // Max 50 per page
    const skip = (pageNum - 1) * limitNum;

    // Get total count
    const total = await Newsletter.countDocuments(query);

    // Get paginated results
    const subscribers = await Newsletter.find(query)
      .sort({ subscribedAt: -1 })
      .skip(skip)
      .limit(limitNum)
      .select('-__v');

    res.status(200).json({
      success: true,
      data: subscribers,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum)
      }
    });

  } catch (err) {
    console.error('Admin newsletter subscribers error:', err);
    res.status(500).json({ 
      success: false, 
      message: 'Server error. Please try again later.' 
    });
  }
});

// JSON-only error handler (prevents HTML error pages)
app.use((err, req, res, _next) => {
  console.error('Unhandled error:', err);
  const status =
    (Number.isInteger(err?.status) && err.status) ||
    (Number.isInteger(err?.code) && err.code) ||
    500;
  const message =
    (typeof err === 'string' && err) ||
    err?.message ||
    'Internal Server Error';
  res.status(status).type('application/json').json({ error: true, message });
});

// Start HTTP immediately for Azure warmup
app.listen(PORT, '0.0.0.0', () => console.log(`HTTP listening on ${PORT}`));

// Connect to MongoDB after server start; do not exit on failure
mongoose.connect(cfg.mongodbUri, { serverSelectionTimeoutMS: 15000 })
  .then(() => {
    console.log('✅ Mongo connected');
    dbReady = true;
    // Initial Instagram sync after DB is ready
    (async () => {
      try {
        const [instagramCount, facebookCount, twitterCount, youtubeCount] = await Promise.all([
          syncInstagramPosts(),
          syncFacebookPosts(),
          syncTwitterTweets(),
          syncYouTubeVideos()
        ]);
        console.log(`🚀 Initial sync done. Instagram: ${instagramCount}, Facebook: ${facebookCount}, Twitter: ${twitterCount}, YouTube: ${youtubeCount}`);  
      } catch (e) {
        console.error('Initial sync failed:', e?.message || e);
      }
    })();
  })
  .catch(err => {
    console.error('❌ Mongo connect failed (server still running):', err.message);
  });

  cron.schedule('*/30 * * * *', async () => {
    try {
      if (!dbReady) return;
      const [instagramCount, facebookCount, youtubeCount] = await Promise.all([
        syncInstagramPosts().catch(err => {
          console.error('Cron Instagram sync failed:', err.message);
          return 0;
        }),
        syncFacebookPosts().catch(err => {
          console.error('Cron Facebook sync failed:', err.message);
          return 0;
        }),
        syncYouTubeVideos().catch(err => {
          console.error('Cron YouTube sync failed:', err.message);
          return 0;
        })
      ]);
      console.log(`⏱️ Cron sync complete. Instagram: ${instagramCount}, Facebook: ${facebookCount}, YouTube: ${youtubeCount}`);
    } catch (err) {
      console.error('Cron sync error:', err.message);
    }
  });
  
  // Twitter sync every 10 minutes
  cron.schedule('*/10 * * * *', async () => {
    try {
      if (!dbReady) return;
      const twitterCount = await syncTwitterTweets().catch(err => {
        console.error('Cron Twitter sync failed:', err.message);
        return 0;
      });
      console.log(`⏱️ Cron sync complete. Twitter: ${twitterCount}`);
    } catch (err) {
      console.error('Cron Twitter sync error:', err.message);
    }
  });

process.on('unhandledRejection', (reason) => {
  console.error('unhandledRejection', reason);
  // keep process alive for warmup; consider restart policy outside
});
process.on('uncaughtException', (err) => {
  console.error('uncaughtException', err);
  // keep process alive for warmup; consider restart policy outside
});