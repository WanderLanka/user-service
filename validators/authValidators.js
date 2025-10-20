const { body } = require('express-validator');

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
    .customSanitizer((value) => {
      if (!value) return value;
      const normalized = String(value).toLowerCase().trim();
      const aliasToCanonical = {
        tourist: 'traveler',
        traveller: 'traveler',
      };
      return aliasToCanonical[normalized] || normalized;
    })
    .isIn(['traveler', 'transport', 'accommodation', 'guide'])
    .withMessage('Invalid role selected')
];

const validateLogin = [
  body().custom((value, { req }) => {
    const { identifier, username } = req.body;
    if (!identifier && !username) {
      throw new Error('Username or email is required');
    }
    return true;
  }),
  body('password')
    .notEmpty()
    .withMessage('Password is required')
];

const validateForgotPassword = [
  body('email')
    .isEmail()
    .withMessage('Please enter a valid email address')
    .normalizeEmail()
];

const validateVerifyOTP = [
  body('email')
    .isEmail()
    .withMessage('Please enter a valid email address')
    .normalizeEmail(),
  body('otp')
    .isLength({ min: 6, max: 6 })
    .withMessage('OTP must be exactly 6 digits')
    .isNumeric()
    .withMessage('OTP must contain only numbers')
];

const validateResetPassword = [
  body('email')
    .isEmail()
    .withMessage('Please enter a valid email address')
    .normalizeEmail(),
  body('otp')
    .isLength({ min: 6, max: 6 })
    .withMessage('OTP must be exactly 6 digits')
    .isNumeric()
    .withMessage('OTP must contain only numbers'),
  body('newPassword')
    .isLength({ min: 8 })
    .withMessage('Password must be at least 8 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>])/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character')
];

module.exports = { 
  validateSignup, 
  validateLogin, 
  validateForgotPassword, 
  validateVerifyOTP, 
  validateResetPassword 
};
