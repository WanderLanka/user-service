const express = require('express');
const router = express.Router();
const { verifyUnifiedToken } = require('../middleware/auth');
const { getProfile, updateProfile, getAccountStatus } = require('../controllers/profileController');

/**
 * @route   GET /profile
 * @desc    Get user profile
 * @access  Private
 */
router.get('/profile', verifyUnifiedToken, getProfile);

/**
 * @route   PUT /profile
 * @desc    Update user profile (username, email)
 * @access  Private
 */
router.put('/profile', verifyUnifiedToken, updateProfile);

/**
 * @route   GET /profile/status
 * @desc    Get account status
 * @access  Private
 */
router.get('/profile/status', verifyUnifiedToken, getAccountStatus);

module.exports = router;
