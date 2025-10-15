const AuthService = require('../services/authService');
const User = require('../models/User');
const { responseHelper, platformHelper, logger } = require('../utils');

// Health check
const healthCheck = (req, res) => {
  const data = {
    status: 'OK',
    message: 'WanderLanka User Service is running',
    timestamp: new Date().toISOString(),
    services: {
      database: User.db && User.db.readyState === 1 ? 'connected' : 'disconnected'
    }
  };
  
  return responseHelper.sendResponse(req, res, data, 'Service is healthy');
};

// Register endpoint - unified for web and mobile
const register = async (req, res) => {
  try {
    // Validate request
    AuthService.validateRequest(req);

    // Detect platform
    const platform = platformHelper.detectPlatform(req);
    
    // Log attempt
    logger.auth('Registration', platform, req.body.username);

    // Register user
    const result = await AuthService.register(req.body, platform);

    // Log success
    logger.authSuccess('Registration', platform, req.body.username);

    // Send response based on platform and result
    if (result.accessToken) {
      return responseHelper.sendResponse(req, res, result, 'User registered successfully', 201);
    } else {
      return responseHelper.sendResponse(req, res, result, 'Guide registration submitted successfully. Your application will be reviewed by admin.', 201);
    }
  } catch (err) {
    logger.error('Registration error:', err);
    return responseHelper.sendError(req, res, err.message, 'Registration failed', 400);
  }
};

// Login endpoint - unified for web and mobile
const login = async (req, res) => {
  try {
    // Validate request
    AuthService.validateRequest(req);

    // Detect platform
    const platform = platformHelper.detectPlatform(req);
    
    // Handle both identifier (mobile) and username (web) formats
    const identifier = req.body.identifier || req.body.username;
    
    // Log attempt
    logger.auth('Login', platform, identifier);

    // Login user
    const result = await AuthService.login(identifier, req.body.password, platform);

    // Log success
    logger.authSuccess('Login', platform, identifier);

    // Send response
    return responseHelper.sendResponse(req, res, result, 'Login successful');
  } catch (err) {
    logger.error('Login error:', err);
    const statusCode = err.message.includes('pending') || err.message.includes('suspended') || err.message.includes('rejected') ? 403 : 401;
    return responseHelper.sendError(req, res, err.message, 'Login failed', statusCode);
  }
};

// Logout endpoint - unified for web and mobile
const logout = async (req, res) => {
  try {
    const result = await AuthService.logout(req.body.refreshToken);
    return responseHelper.sendResponse(req, res, result, result.message);
  } catch (err) {
    logger.error('Logout error:', err);
    return responseHelper.sendError(req, res, err.message, 'Logout failed', 500);
  }
};

// Refresh token endpoint - unified for web and mobile
const refreshToken = async (req, res) => {
  try {
    const result = await AuthService.refreshToken(req.body.refreshToken);
    return responseHelper.sendResponse(req, res, result, 'Token refreshed successfully');
  } catch (err) {
    logger.error('Token refresh error:', err);
    return responseHelper.sendError(req, res, err.message, 'Token refresh failed', 401);
  }
};

// Profile endpoint - unified for web and mobile
const getProfile = async (req, res) => {
  try {
    const result = await AuthService.getProfile(req.user.userId);
    return responseHelper.sendResponse(req, res, { user: result }, 'Profile retrieved successfully');
  } catch (err) {
    logger.error('Profile error:', err);
    return responseHelper.sendError(req, res, err.message, 'Profile not found', 404);
  }
};

// Verify token endpoint - unified for web and mobile
const verifyToken = (req, res) => {
  const data = {
    valid: true,
    user: {
      userId: req.user.userId,
      username: req.user.username,
      role: req.user.role,
      platform: req.user.platform
    }
  };
  
  return responseHelper.sendResponse(req, res, data, 'Token is valid');
};

// Cleanup expired refresh tokens - maintenance endpoint
const cleanupTokens = async (req, res) => {
  try {
    const result = await AuthService.cleanupExpiredTokens();
    return responseHelper.success(res, result, 'Token cleanup completed');
  } catch (err) {
    logger.error('Token cleanup error:', err);
    return responseHelper.error(res, err.message, 'Token cleanup failed', 500);
  }
};

module.exports = {
  healthCheck,
  register,
  login,
  logout,
  refreshToken,
  getProfile,
  verifyToken,
  cleanupTokens
};
