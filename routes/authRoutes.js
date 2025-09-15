const express = require('express');
const router = express.Router();
const authLimiter = require('../middleware/rateLimiter');
const { validateSignup, validateLogin } = require('../validators/authValidators');
const { verifyUnifiedToken } = require('../middleware/auth');
const authController = require('../controllers/authController');

// Health check
router.get('/health', authController.healthCheck);

// Unified authentication endpoints (work for both web and mobile)
router.post('/signup', authLimiter, validateSignup, authController.register);
router.post('/login', authLimiter, validateLogin, authController.login);
router.post('/logout', authController.logout);
router.post('/refresh', authController.refreshToken);
router.get('/profile', verifyUnifiedToken, authController.getProfile);
router.get('/verify-token', verifyUnifiedToken, authController.verifyToken);

// Legacy mobile endpoints (for backward compatibility)
// router.post('/api/auth/signup', authLimiter, validateSignup, authController.register);
// router.post('/api/auth/login', authLimiter, validateLogin, authController.login);
// router.post('/api/auth/logout', authController.logout);
// router.post('/api/auth/refresh', authController.refreshToken);
// router.get('/api/auth/profile', verifyUnifiedToken, authController.getProfile);
// router.get('/api/auth/verify-token', verifyUnifiedToken, authController.verifyToken);

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

// Maintenance endpoint
router.post('/cleanup-tokens', authController.cleanupTokens);

module.exports = router;
