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

/**
 * @route   PUT /profile/account-status
 * @desc    Toggle account active/inactive status
 * @access  Private
 */
router.put('/profile/account-status', verifyUnifiedToken, require('../controllers/profileController').toggleAccountStatus);

/**
 * @route   DELETE /profile/delete-account
 * @desc    Delete user account (soft delete - deactivates account)
 * @access  Private
 */
router.delete('/profile/delete-account', verifyUnifiedToken, require('../controllers/profileController').deleteAccount);

module.exports = router;
