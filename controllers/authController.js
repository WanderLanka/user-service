const AuthService = require('../services/authService');
const User = require('../models/User');
const { responseHelper } = require('../utils');

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
    const result = await AuthService.register(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Registration failed', err.statusCode || 400);
  }
};

// Login endpoint - unified for web and mobile
const login = async (req, res) => {
  try {
    const result = await AuthService.login(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Login failed', err.statusCode || 401);
  }
};

const redirect = async (req, res) => {
  try {
    const result = await AuthService.redirect(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Redirection failed', err.statusCode || 400);
  } 
};

// Logout endpoint - unified for web and mobile
const logout = async (req, res) => {
  try {
    const result = await AuthService.logout(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Logout failed', err.statusCode || 500);
  }
};

// Refresh token endpoint - unified for web and mobile
const refreshToken = async (req, res) => {
  try {
    const result = await AuthService.refreshToken(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Token refresh failed', err.statusCode || 401);
  }
};

// Profile endpoint - unified for web and mobile
const getProfile = async (req, res) => {
  try {
    const result = await AuthService.getProfile(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Profile not found', err.statusCode || 404);
  }
};

// Verify token endpoint - unified for web and mobile
const verifyToken = async (req, res) => {
  try {
    const result = await AuthService.verifyToken(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Token verification failed', err.statusCode || 401);
  }
};

// Cleanup expired refresh tokens - maintenance endpoint
const cleanupTokens = async (req, res) => {
  try {
    const result = await AuthService.cleanupExpiredTokens(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Token cleanup failed', err.statusCode || 500);
  }
};

module.exports = {
  healthCheck,
  register,
  redirect,
  login,
  logout,
  refreshToken,
  getProfile,
  verifyToken,
  cleanupTokens
};
