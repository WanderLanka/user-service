const express = require('express');
const router = express.Router();
const authLimiter = require('../middleware/rateLimiter');
const { validateSignup, validateLogin, validateForgotPassword, validateVerifyOTP, validateResetPassword } = require('../validators/authValidators');
const { verifyUnifiedToken } = require('../middleware/auth');
const authController = require('../controllers/authController');
const multer = require('multer');

// Configure multer for file uploads
const upload = multer({ dest: 'uploads/docs/' });

// Health check
router.get('/health', authController.healthCheck);

// Unified authentication endpoints (work for both web and mobile)
router.post('/signup', authLimiter, validateSignup, authController.register);
router.post('/register', authLimiter, upload.single('document'), validateSignup, authController.register);
router.post('/redirect', authLimiter, upload.single('document'), validateSignup, authController.redirect);
router.post('/login', authLimiter, validateLogin, authController.login);
router.post('/logout', authController.logout);
router.post('/refresh', authController.refreshToken);
router.get('/profile', verifyUnifiedToken, authController.getProfile);
router.get('/verify-token', verifyUnifiedToken, authController.verifyToken);
// Admin: fetch access requests (GET used by frontend admin panel)
router.get('/requests', authController.requests);
// Also keep POST /requests for backward compatibility
router.put('/updateRequestStatus', authController.updateRequestStatus);

// Serve a specific request's document (streams PDF/binary)
router.get('/requests/:id/document', authController.getRequestDocument);

// Legacy guide registration endpoint (mobile) - maps to register with platform override
router.post('/api/auth/guide-registration', authLimiter, (req, res, next) => {
  req.headers['x-platform'] = 'mobile';
  req.body.guideDetails = {
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    nicNumber: req.body.nicNumber,
    dateOfBirth: req.body.dateOfBirth
  };
  next();
}, authController.register);

// Forgot password endpoints
router.post('/forgot-password', authLimiter, validateForgotPassword, authController.forgotPassword);
router.post('/verify-reset-otp', authLimiter, validateVerifyOTP, authController.verifyResetOTP);
router.post('/reset-password', authLimiter, validateResetPassword, authController.resetPassword);

// Maintenance endpoints
router.post('/cleanup-tokens', authController.cleanupTokens);
router.post('/cleanup-expired-otps', authController.cleanupExpiredOTPs);

module.exports = router;