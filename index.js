require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const app = express();

// Rate limiting
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    error: 'Too many authentication attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
app.use(cors({ 
  origin: [
    'http://localhost:5173', 
    'http://192.168.8.159:8081', 
    'exp://192.168.8.159:8081',
    'http://192.168.8.142:8081',
    'exp://192.168.8.142:8081'
  ], 
  credentials: true 
}));
app.use(express.json());

// Add request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - ${req.get('User-Agent') || 'Unknown'}`);
  next();
});

// Enhanced User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    required: true,
    enum: ['tourist', 'traveller', 'transport', 'accommodation', 'guide'],
    default: 'tourist'
  },
  status: {
    type: String,
    enum: ['active', 'pending', 'suspended', 'rejected'],
    default: 'active' // Default for regular users, guides will be 'pending'
  },
  platform: {
    type: String,
    enum: ['web', 'mobile'],
    default: 'web'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  avatar: {
    type: String,
    default: null
  },
  // Guide-specific details
  guideDetails: {
    firstName: String,
    lastName: String,
    nicNumber: String,
    dateOfBirth: String,
    proofDocument: String, // Will store file path or URL
    approvedAt: {
      type: Date,
      default: null
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null
    }
  },
  refreshTokens: [{
    token: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for better performance
userSchema.index({ username: 1, email: 1 });
userSchema.index({ refreshTokens: 1 });

const User = mongoose.model('User', userSchema);

// Database connection with better error handling
const connectDB = async () => {
  try {
    const mongoUri = process.env.MONGO_URI || 'mongodb://localhost:27017/wanderlanka';
    console.log('Connecting to MongoDB:', mongoUri.replace(/mongodb\+srv:\/\/[^:]+:[^@]+@/, 'mongodb+srv://****:****@'));
    
    await mongoose.connect(mongoUri);
    
    console.log('✅ MongoDB connected successfully');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    process.exit(1);
  }
};

// Utility functions
const generateTokens = (user, platform = 'web') => {
  const jwtSecret = process.env.JWT_SECRET || 'fallback-secret-key';
  
  const accessToken = jwt.sign(
    { 
      userId: user._id, 
      username: user.username, 
      role: user.role,
      platform 
    },
    jwtSecret,
    { expiresIn: '24h' }
  );

  const refreshToken = jwt.sign(
    { 
      userId: user._id,
      type: 'refresh',
      platform
    },
    jwtSecret,
    { expiresIn: '7d' }
  );

  return { accessToken, refreshToken };
};

const hashPassword = async (password) => {
  const saltRounds = 12;
  return await bcrypt.hash(password, saltRounds);
};

// Validation middleware
const validateSignup = [
  body('username')
    .isLength({ min: 3, max: 30 })
    .withMessage('Username must be between 3 and 30 characters')
    .matches(/^[a-zA-Z0-9_]+$/)
    .withMessage('Username can only contain letters, numbers, and underscores'),
  body('email')
    .isEmail()
    .withMessage('Please enter a valid email address')
    .normalizeEmail(),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number'),
  body('role')
    .isIn(['tourist', 'transport', 'accommodation', 'guide'])
    .withMessage('Invalid role selected')
];

const validateLogin = [
  body('identifier').notEmpty().withMessage('Username or email is required'),
  body('password').notEmpty().withMessage('Password is required')
];

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    message: 'WanderLanka User Service is running',
    timestamp: new Date().toISOString(),
    services: {
      database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
    }
  });
});

// ================================
// WEB APP ROUTES (Keep existing)
// ================================


// Register endpoint (Web App - Keep existing)
app.post('/register', authLimiter, async (req, res) => {
  try {
    console.log('WEB Registration attempt:', { ...req.body, password: '[HIDDEN]' });
    
    const { username, email, password, role } = req.body;

    // Validate required fields
    if (!username || !email || !password || !role) {
      console.log('Missing required fields');
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Validate role for web app (transport, accommodation only)
    const validWebRoles = ['transport', 'accommodation'];
    if (!validWebRoles.includes(role)) {
      console.log('Invalid web app role:', role);
      return res.status(400).json({ error: 'Invalid role for web application' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }] 
    });
    
    if (existingUser) {
      console.log('User already exists:', existingUser.username);
      return res.status(400).json({ 
        error: existingUser.username === username ? 'Username already exists' : 'Email already exists' 
      });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role,
      platform: 'web'
    });

    await newUser.save();
    console.log('Web user created successfully:', username);

    // Generate JWT token
    const { accessToken } = generateTokens(newUser, 'web');

    res.status(201).json({
      message: 'User registered successfully',
      token: accessToken,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });

  } catch (err) {
    console.error('Web registration error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login endpoint (Web App - Keep existing)
app.post('/login', authLimiter, async (req, res) => {
  try {
    console.log('WEB Login attempt:', { username: req.body.username, password: '[HIDDEN]' });
    
    const { username, password } = req.body;

    // Validate required fields
    if (!username || !password) {
      console.log('Missing username or password');
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find web user by username
    const user = await User.findOne({ 
      username, 
      platform: 'web',
      role: { $in: ['transport', 'accommodation'] }
    });
    
    if (!user) {
      console.log('Web user not found:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Password mismatch for web user:', username);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const { accessToken } = generateTokens(user, 'web');

    console.log('Web login successful for user:', username);

    res.status(200).json({
      message: 'Login successful',
      token: accessToken,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (err) {
    console.error('Web login error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ================================
// MOBILE APP ROUTES (New)
// ================================

// Mobile App Signup
app.post('/api/auth/signup', authLimiter, validateSignup, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        error: errors.array()[0].msg
      });
    }

    console.log('MOBILE Registration attempt:', { ...req.body, password: '[HIDDEN]' });
    
    const { username, email, password, role } = req.body;

    // Validate role for mobile app (tourist, guide only)
    const validMobileRoles = ['tourist', 'guide'];
    if (!validMobileRoles.includes(role)) {
      console.log('Invalid mobile app role:', role);
      return res.status(400).json({ 
        success: false,
        message: 'Invalid role for mobile application',
        error: 'Role must be either tourist or guide'
      });
    }

    // Map 'tourist' to 'traveller' as used in mobile app types
    const mappedRole = role === 'tourist' ? 'traveller' : role;

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ username }, { email }] 
    });
    
    if (existingUser) {
      console.log('Mobile user already exists:', existingUser.username);
      return res.status(400).json({ 
        success: false,
        message: existingUser.username === username ? 'Username already exists' : 'Email already exists',
        error: existingUser.username === username ? 'Username already exists' : 'Email already exists'
      });
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Determine initial status based on role
    const initialStatus = mappedRole === 'guide' ? 'pending' : 'active';

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      role: mappedRole,
      platform: 'mobile',
      status: initialStatus, // Guides start as pending, travelers as active
      isActive: true,
      emailVerified: false
    });

    await newUser.save();
    console.log('Mobile user created successfully:', username, 'with status:', initialStatus);

    // Only generate tokens for active users (not pending guides)
    if (initialStatus === 'active') {
      // Generate tokens
      const { accessToken, refreshToken } = generateTokens(newUser, 'mobile');

      // Store refresh token in database
      const refreshTokenExpiry = new Date();
      refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7); // 7 days

      newUser.refreshTokens.push({
        token: refreshToken,
        expiresAt: refreshTokenExpiry
      });
      await newUser.save();

      res.status(201).json({
        success: true,
        message: 'User registered successfully',
        data: {
          user: {
            id: newUser._id.toString(),
            username: newUser.username,
            email: newUser.email,
            role: mappedRole,
            status: newUser.status,
            avatar: newUser.avatar,
            isActive: newUser.isActive,
            emailVerified: newUser.emailVerified,
            createdAt: newUser.createdAt,
            updatedAt: newUser.updatedAt
          },
          accessToken,
          refreshToken
        }
      });
    } else {
      // For pending guides, don't provide tokens
      res.status(201).json({
        success: true,
        message: 'Guide registration submitted successfully. Your application will be reviewed by admin.',
        data: {
          user: {
            id: newUser._id.toString(),
            username: newUser.username,
            email: newUser.email,
            role: mappedRole,
            status: newUser.status,
            avatar: newUser.avatar,
            isActive: newUser.isActive,
            emailVerified: newUser.emailVerified,
            createdAt: newUser.createdAt,
            updatedAt: newUser.updatedAt
          }
        }
      });
    }  } catch (err) {
    console.error('Mobile registration error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: 'Registration failed. Please try again.'
    });
  }
});

// Mobile App Login
app.post('/api/auth/login', authLimiter, validateLogin, async (req, res) => {
  try {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        message: 'Validation failed',
        error: errors.array()[0].msg
      });
    }

    console.log('MOBILE Login attempt:', { identifier: req.body.identifier, password: '[HIDDEN]' });
    
    const { identifier, password } = req.body;

    // Find mobile user by username or email
    const user = await User.findOne({ 
      $or: [{ username: identifier }, { email: identifier }],
      platform: 'mobile',
      role: { $in: ['traveller', 'guide'] },
      isActive: true
    });
    
    if (!user) {
      console.log('Mobile user not found:', identifier);
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials',
        error: 'Invalid username/email or password'
      });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log('Password mismatch for mobile user:', identifier);
      return res.status(401).json({ 
        success: false,
        message: 'Invalid credentials',
        error: 'Invalid username/email or password'
      });
    }

    // Check if guide account is pending approval
    if (user.role === 'guide' && user.status === 'pending') {
      console.log('Guide account pending approval:', identifier);
      return res.status(403).json({ 
        success: false,
        message: 'Account pending approval',
        error: 'Your guide account is still under review. Please wait for admin approval.'
      });
    }

    // Check if account is suspended or rejected
    if (user.status === 'suspended') {
      console.log('Account suspended:', identifier);
      return res.status(403).json({ 
        success: false,
        message: 'Account suspended',
        error: 'Your account has been suspended. Please contact support.'
      });
    }

    if (user.status === 'rejected') {
      console.log('Account rejected:', identifier);
      return res.status(403).json({ 
        success: false,
        message: 'Account rejected',
        error: 'Your guide application has been rejected. Please contact support for more information.'
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user, 'mobile');

    // Store refresh token in database
    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7); // 7 days

    user.refreshTokens.push({
      token: refreshToken,
      expiresAt: refreshTokenExpiry
    });
    await user.save();

    console.log('Mobile login successful for user:', identifier);

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user._id.toString(),
          username: user.username,
          email: user.email,
          role: user.role,
          status: user.status,
          avatar: user.avatar,
          isActive: user.isActive,
          emailVerified: user.emailVerified,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt
        },
        accessToken,
        refreshToken
      }
    });

  } catch (err) {
    console.error('Mobile login error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: 'Login failed. Please try again.'
    });
  }
});

// Mobile App Logout
app.post('/api/auth/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken) {
      // Remove refresh token from database
      await User.updateOne(
        { 'refreshTokens.token': refreshToken },
        { $pull: { refreshTokens: { token: refreshToken } } }
      );
      console.log('Refresh token removed from database');
    }

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (err) {
    console.error('Mobile logout error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: 'Logout failed'
    });
  }
});

// Mobile App Token Refresh
app.post('/api/auth/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        message: 'Refresh token required',
        error: 'No refresh token provided'
      });
    }

    // Verify refresh token
    const jwtSecret = process.env.JWT_SECRET || 'fallback-secret-key';
    let decoded;
    
    try {
      decoded = jwt.verify(refreshToken, jwtSecret);
    } catch (err) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
        error: 'Token verification failed'
      });
    }

    // Find user and validate refresh token
    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'User not found',
        error: 'Invalid refresh token'
      });
    }

    const tokenExists = user.refreshTokens.some(
      tokenObj => tokenObj.token === refreshToken && tokenObj.expiresAt > new Date()
    );

    if (!tokenExists) {
      return res.status(401).json({
        success: false,
        message: 'Invalid refresh token',
        error: 'Token not found or expired'
      });
    }

    // Generate new tokens
    const { accessToken, refreshToken: newRefreshToken } = generateTokens(user, 'mobile');

    // Replace old refresh token with new one
    await User.updateOne(
      { _id: user._id },
      { 
        $pull: { refreshTokens: { token: refreshToken } },
        updatedAt: new Date()
      }
    );

    const refreshTokenExpiry = new Date();
    refreshTokenExpiry.setDate(refreshTokenExpiry.getDate() + 7);

    await User.updateOne(
      { _id: user._id },
      { 
        $push: { 
          refreshTokens: {
            token: newRefreshToken,
            expiresAt: refreshTokenExpiry
          }
        }
      }
    );

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        user: {
          id: user._id.toString(),
          username: user.username,
          email: user.email,
          role: user.role,
          avatar: user.avatar,
          isActive: user.isActive,
          emailVerified: user.emailVerified,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt
        },
        accessToken,
        refreshToken: newRefreshToken
      }
    });

  } catch (err) {
    console.error('Token refresh error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: 'Token refresh failed'
    });
  }
});

// Guide registration endpoint for mobile app
app.post('/api/auth/guide-registration', authLimiter, async (req, res) => {
  try {
    console.log('📝 Guide registration request received');
    console.log('📝 Request body fields:', Object.keys(req.body));
    
    const {
      username,
      email,
      password,
      role,
      firstName,
      lastName,
      nicNumber,
      dateOfBirth
    } = req.body;

    // Validate required fields
    if (!username || !email || !password || !firstName || !lastName || !nicNumber || !dateOfBirth) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Validate role
    if (role !== 'guide') {
      return res.status(400).json({
        success: false,
        message: 'Invalid role for guide registration'
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email }, { username }]
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create new guide user (with pending approval)
    const newGuide = new User({
      username,
      email,
      password: hashedPassword,
      role: 'guide',
      platform: 'mobile', // Set platform for mobile app users
      status: 'pending', // Guides need admin approval
      guideDetails: {
        firstName,
        lastName,
        nicNumber,
        dateOfBirth,
        // proofDocument will be handled separately if needed
      },
      createdAt: new Date()
    });

    await newGuide.save();

    console.log('✅ Guide registration successful for:', username);

    res.status(201).json({
      success: true,
      message: 'Guide registration submitted successfully. Your application will be reviewed by admin.',
      data: {
        user: {
          id: newGuide._id,
          username: newGuide.username,
          email: newGuide.email,
          role: newGuide.role,
          status: newGuide.status
        }
      }
    });

  } catch (err) {
    console.error('❌ Guide registration error:', err);
    
    if (err.code === 11000) {
      // Duplicate key error
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }

    res.status(500).json({
      success: false,
      message: 'Guide registration failed. Please try again.'
    });
  }
});

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const jwtSecret = process.env.JWT_SECRET || 'fallback-secret-key';
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(400).json({ error: 'Invalid token' });
  }
};

// Mobile middleware to verify JWT token with proper response format
const verifyMobileToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: 'Access denied',
      error: 'No token provided'
    });
  }

  try {
    const jwtSecret = process.env.JWT_SECRET || 'fallback-secret-key';
    const decoded = jwt.verify(token, jwtSecret);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Mobile token verification error:', err);
    res.status(401).json({ 
      success: false,
      message: 'Invalid token',
      error: 'Token verification failed'
    });
  }
};

// Mobile App Profile endpoint
app.get('/api/auth/profile', verifyMobileToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password -refreshTokens');
    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'User not found',
        error: 'Profile not found'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Profile retrieved successfully',
      data: {
        user: {
          id: user._id.toString(),
          username: user.username,
          email: user.email,
          role: user.role,
          status: user.status,
          avatar: user.avatar,
          isActive: user.isActive,
          emailVerified: user.emailVerified,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt
        }
      }
    });
  } catch (err) {
    console.error('Mobile profile error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Internal server error',
      error: 'Failed to retrieve profile'
    });
  }
});

// Mobile App Verify Token endpoint
app.get('/api/auth/verify-token', verifyMobileToken, (req, res) => {
  res.json({ 
    success: true,
    message: 'Token is valid',
    data: { 
      valid: true, 
      user: {
        userId: req.user.userId,
        username: req.user.username,
        role: req.user.role,
        platform: req.user.platform
      }
    }
  });
});

// ================================
// SHARED/WEB ROUTES (Keep existing)
// ================================

// Protected route example (Web - Keep existing)
app.get('/profile', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (err) {
    console.error('Profile error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Verify token endpoint (Web - Keep existing)
app.get('/verify-token', verifyToken, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// Cleanup expired refresh tokens (maintenance endpoint)
app.post('/api/auth/cleanup-tokens', async (req, res) => {
  try {
    const result = await User.updateMany(
      {},
      {
        $pull: {
          refreshTokens: {
            expiresAt: { $lt: new Date() }
          }
        }
      }
    );

    res.status(200).json({
      success: true,
      message: 'Token cleanup completed',
      data: {
        modifiedCount: result.modifiedCount
      }
    });
  } catch (err) {
    console.error('Token cleanup error:', err);
    res.status(500).json({ 
      success: false,
      message: 'Token cleanup failed',
      error: err.message
    });
  }
});

// Start server
const startServer = async () => {
  try {
    await connectDB();
    
    const PORT = process.env.PORT || 3001;
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🔐 Auth service running on port ${PORT}`);
      console.log(`🌐 Health check: http://localhost:${PORT}/health`);
      console.log(`🌐 Mobile access: http://192.168.8.159:${PORT}/health`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

startServer();