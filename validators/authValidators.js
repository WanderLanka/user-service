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
    .isIn(['traveler', 'transport', 'accommodation', 'guide'])  // Mobile sends 'traveler', web sends all roles
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

module.exports = { validateSignup, validateLogin };
