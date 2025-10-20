const AuthService = require('../services/authService');
const ForgotPasswordService = require('../services/forgotPasswordService');
const User = require('../models/User');
const Tempuser = require('../models/Tempuser');
const fs = require('fs');
const path = require('path');
const { responseHelper } = require('../utils');
const { default: Adminservice } = require('../services/adminservice');

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

const requests=async(req,res)=>{
  try{
    const result= await Adminservice.requests(req);
    return responseHelper.sendResponse(req, res, result, 'Requests fetched successfully', 200);
  }   
  catch(err){
    return responseHelper.sendError(req, res, err.message, 'Fetching requests failed', err.statusCode || 500);
  } 
};

// Stream attached document (PDF) for a given access request
const getRequestDocument = async (req, res) => {
  try {
    const { id } = req.params;
    const tempuser = await Tempuser.findById(id);
    if (!tempuser) {
      return responseHelper.sendError(req, res, 'Request not found', 'Not Found', 404);
    }

    // 1) If stored as a filesystem path (multer disk storage)
    if (tempuser.document && typeof tempuser.document === 'string') {
      const rawPath = tempuser.document;
      const absolutePath = path.isAbsolute(rawPath)
        ? rawPath
        : path.join(process.cwd(), rawPath.replace(/^\/*/, ''));

      if (fs.existsSync(absolutePath)) {
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'inline; filename="document.pdf"');
        return fs.createReadStream(absolutePath).pipe(res);
      }
    }

    // 2) If stored as a Mongo binary buffer under common patterns
    //    a) tempuser.document = { data: Buffer, contentType, filename }
    if (tempuser.document && typeof tempuser.document === 'object' && tempuser.document.data) {
      const contentType = tempuser.document.contentType || 'application/pdf';
      const filename = tempuser.document.filename || 'document.pdf';
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
      return res.status(200).send(Buffer.from(tempuser.document.data));
    }

    //    b) Separate fields: documentBuffer, documentMime, documentName
    if (tempuser.documentBuffer && Buffer.isBuffer(tempuser.documentBuffer)) {
      const contentType = tempuser.documentMime || 'application/pdf';
      const filename = tempuser.documentName || 'document.pdf';
      res.setHeader('Content-Type', contentType);
      res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
      return res.status(200).send(tempuser.documentBuffer);
    }

    return responseHelper.sendError(req, res, 'Document not found for this request', 'Not Found', 404);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Failed to load document', err.statusCode || 500);
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

// Update request status (approve/reject) - used by admin UI
const updateRequestStatus = async (req, res) => {
  try {
    const { requestId, action } = req.body;
    if (!requestId || !action) throw new Error('requestId and action are required');
    const result = await Adminservice.updateRequestStatus(requestId, action);
    return responseHelper.sendResponse(req, res, result, 'Request updated', 200);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Update request failed', err.statusCode || 400);
  }
};

// Forgot password endpoints
const forgotPassword = async (req, res) => {
  try {
    const result = await ForgotPasswordService.requestPasswordReset(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Password reset request failed', err.statusCode || 400);
  }
};

const verifyResetOTP = async (req, res) => {
  try {
    const result = await ForgotPasswordService.verifyPasswordResetOTP(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'OTP verification failed', err.statusCode || 400);
  }
};

const resetPassword = async (req, res) => {
  try {
    const result = await ForgotPasswordService.resetPassword(req);
    return responseHelper.sendResponse(req, res, result.data, result.message, result.statusCode);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'Password reset failed', err.statusCode || 400);
  }
};

// Cleanup expired OTPs - maintenance endpoint
const cleanupExpiredOTPs = async (req, res) => {
  try {
    const result = await ForgotPasswordService.cleanupExpiredOTPs();
    return responseHelper.sendResponse(req, res, result, 'Expired OTPs cleaned up successfully', 200);
  } catch (err) {
    return responseHelper.sendError(req, res, err.message, 'OTP cleanup failed', err.statusCode || 500);
  }
};

// Get user by ID endpoint - allows authenticated users to view other user profiles
const getUserById = async (req, res) => {
  try {
    const { userId } = req.params;
    
    if (!userId) {
      return responseHelper.sendError(req, res, 'User ID is required', 'Invalid Request', 400);
    }
    
    const UserService = require('../services/userService');
    const user = await UserService.getUserProfile(userId);
    
    if (!user) {
      return responseHelper.sendError(req, res, 'User not found', 'Not Found', 404);
    }
    
    const userData = UserService.formatUserResponse(user);
    
    return responseHelper.sendResponse(req, res, { user: userData }, 'User details retrieved successfully', 200);
  } catch (err) {
    console.error('Error fetching user by ID:', err);
    return responseHelper.sendError(req, res, err.message, 'Failed to fetch user details', err.statusCode || 500);
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
  getUserById,
  cleanupTokens,
  updateRequestStatus,
  requests,
  getRequestDocument,
  forgotPassword,
  verifyResetOTP,
  resetPassword,
  cleanupExpiredOTPs
};
