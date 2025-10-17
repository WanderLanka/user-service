const UserService = require('./userService');
const TokenService = require('./tokenService');
const { validationResult } = require('express-validator');
const { platformHelper, logger } = require('../utils');

class AuthService {
    
  static validateRequest(req) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(error => error.msg);
      throw new Error(errorMessages.join(', '));
    }
  }

  static async register(req) {
    // Validate request
    this.validateRequest(req);

    // Detect platform
    const platform = platformHelper.detectPlatform(req);
    console.log('Detected platform:', platform, 'Role received:', req.body.role);

    // Log attempt
    logger.auth('Registration', platform, req.body.username);

    // Check if user already exists
    const existingUser = await UserService.findByUsernameOrEmail(req.body.username, req.body.email);
    if (existingUser) {
      const error = new Error(existingUser.username === req.body.username ? 'Username already exists' : 'Email already exists');
      error.statusCode = 409;
      throw error;
    }

    // Determine role and status based on platform and role
    let role = req.body.role;
    let status = 'active';

    if (platform === 'web') {
      const validWebRoles = ['traveler', 'transport', 'accommodation', 'Sysadmin'];  // Web: all EXCEPT guide
      if (!validWebRoles.includes(role)) {
        const error = new Error('Invalid role for web application');
        error.statusCode = 400;
        throw error;
      }
    } else if (platform === 'mobile') {
      const validMobileRoles = ['traveler', 'guide'];  // Mobile: ONLY traveler and guide
      if (!validMobileRoles.includes(role)) {
        const error = new Error('Role must be either traveler or guide');
        error.statusCode = 400;
        throw error;
      }
      // For mobile, map traveler to traveller in database
      if (role === 'traveler') role = 'traveller';
      // Guides need admin approval
      if (role === 'guide') status = 'pending';
    }

    // Create user
    const newUser = await UserService.createUser({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
      role,
      platform,
      status,
      isActive: true,
      emailVerified: false,
      guideDetails: req.body.guideDetails || null
    });

    // Log success
    logger.authSuccess('Registration', platform, req.body.username);

    // Registration only returns user data, no tokens
    // Users must login separately to get tokens
    const userData = UserService.formatUserResponse(newUser, false);
    
    // Return structured response based on user role and status
    const message = (newUser.role === 'guide' && newUser.status === 'pending') 
      ? 'Guide registration submitted successfully. Your application will be reviewed by admin.' 
      : 'User registered successfully. Please login to access your account.';
    
    return {
      data: userData,
      message,
      statusCode: 201
    };
  }

  static async login(req) {
    // Validate request
    this.validateRequest(req);

    // Detect platform
    const platform = platformHelper.detectPlatform(req);
    
    // Handle both identifier (mobile) and username (web) formats
    const identifier = req.body.identifier || req.body.username;
    
    // Log attempt
    logger.auth('Login', platform, identifier);

    // Find user
    const user = await UserService.findByCredentials(identifier);
    if (!user) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    }

    // Platform-specific role validation
    if (platform === 'web' && !['traveler', 'transport', 'accommodation', 'Sysadmin'].includes(user.role)) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    } else if (platform === 'mobile' && !['traveller', 'guide'].includes(user.role)) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    }

    // Verify password
    const isPasswordValid = await TokenService.comparePassword(req.body.password, user.password);
    if (!isPasswordValid) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    }

    // Check account status
    if (user.role === 'guide' && user.status === 'pending') {
      const error = new Error('Your guide account is still under review. Please wait for admin approval.');
      error.statusCode = 403;
      throw error;
    }

    if (user.status === 'suspended') {
      const error = new Error('Your account has been suspended. Please contact support.');
      error.statusCode = 403;
      throw error;
    }

    if (user.status === 'rejected') {
      const error = new Error('Your guide application has been rejected. Please contact support for more information.');
      error.statusCode = 403;
      throw error;
    }

    // Generate tokens
    const tokens = TokenService.generateTokens(user, platform);
    await UserService.addRefreshToken(user._id, tokens.refreshToken);

    // Log success
    logger.authSuccess('Login', platform, identifier);

    const userData = UserService.formatUserResponse(user, true, tokens);
    
    return {
      data: userData,
      message: 'Login successful',
      statusCode: 200
    };
  }

  static async logout(req) {
    const refreshToken = req.body.refreshToken;
    
    if (refreshToken) {
      await UserService.removeRefreshToken(refreshToken);
    }
    
    return {
      data: {},
      message: 'Logged out successfully',
      statusCode: 200
    };
  }

  static async refreshToken(req) {
    const refreshToken = req.body.refreshToken;
    
    if (!refreshToken) {
      const error = new Error('No refresh token provided');
      error.statusCode = 400;
      throw error;
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = TokenService.verifyToken(refreshToken);
    } catch (err) {
      const error = new Error('Token verification failed');
      error.statusCode = 401;
      throw error;
    }

    // Find user and validate refresh token
    const user = await UserService.findValidRefreshToken(decoded.userId, refreshToken);
    if (!user) {
      const error = new Error('Invalid refresh token');
      error.statusCode = 401;
      throw error;
    }

    // Generate new tokens
    const tokens = TokenService.generateTokens(user, decoded.platform);
    await UserService.addRefreshToken(user._id, tokens.refreshToken);
    await UserService.removeRefreshToken(refreshToken);

    const userData = UserService.formatUserResponse(user, true, tokens);
    
    return {
      data: userData,
      message: 'Token refreshed successfully',
      statusCode: 200
    };
  }
  static async getProfile(req) {
    const userId = req.user.userId;
    
    const user = await UserService.getUserProfile(userId);
    if (!user) {
      const error = new Error('Profile not found');
      error.statusCode = 404;
      throw error;
    }
    
    const userData = UserService.formatUserResponse(user);
    
    return {
      data: { user: userData },
      message: 'Profile retrieved successfully',
      statusCode: 200
    };
  }

  static async verifyToken(req) {
    const userData = {
      valid: true,
      user: {
        userId: req.user.userId,
        username: req.user.username,
        role: req.user.role,
        platform: req.user.platform
      }
    };
    
    return {
      data: userData,
      message: 'Token is valid',
      statusCode: 200
    };
  }

  static async cleanupExpiredTokens(req) {
    const result = await UserService.cleanupExpiredTokens();
    
    return {
      data: { modifiedCount: result.modifiedCount },
      message: 'Token cleanup completed',
      statusCode: 200
    };
  }
}

module.exports = AuthService;
