const User = require('../models/User');
const { logger, responseHelper } = require('../utils');

/**
 * Get user profile
 * @route GET /profile
 * @access Private
 */
const getProfile = async (req, res) => {
  try {
    const userId = req.user.userId;
    logger.info(`Fetching profile for user: ${userId}`);

    const user = await User.findById(userId).select('-password -refreshTokens');

    if (!user) {
      logger.warn(`User not found: ${userId}`);
      return responseHelper.sendError(req, res, 'User not found', 'Not Found', 404);
    }

    // Format response for mobile app
    const profileData = {
      id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName || user.username,
      phone: user.phone || null,
      avatar: user.avatar,
      role: user.role,
      status: user.status,
      isActive: user.isActive,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified || false,
      platform: user.platform,
      memberSince: user.createdAt,
      verified: user.emailVerified,
      bio: user.bio || null,
      dateOfBirth: user.dateOfBirth || null,
      gender: user.gender || null,
      nationality: user.nationality || null,
      passportNumber: user.passportNumber || null,
      emergencyContact: user.emergencyContact || {
        name: null,
        phone: null,
        relationship: null
      },
      preferences: user.preferences || {
        budget: null,
        accommodation: null,
        dietary: null,
        interests: []
      },
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    logger.info(`Profile fetched successfully for user: ${userId}`);
    return responseHelper.sendResponse(req, res, profileData, 'Profile fetched successfully', 200);

  } catch (error) {
    logger.error('Error fetching profile:', error);
    return responseHelper.sendError(req, res, 'Failed to fetch profile', 'Server Error', 500);
  }
};

/**
 * Update user profile
 * @route PUT /profile
 * @access Private
 */
const updateProfile = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { 
      username, 
      email, 
      fullName, 
      phone, 
      bio, 
      dateOfBirth, 
      gender, 
      nationality, 
      passportNumber,
      emergencyContact,
      preferences
    } = req.body;

    logger.info(`🔄 Updating profile for user: ${userId}`);
    logger.info(`📝 Update data received:`, { 
      username, 
      email, 
      fullName, 
      phone, 
      bio, 
      dateOfBirth, 
      gender, 
      nationality, 
      passportNumber,
      emergencyContact,
      preferences
    });

    // Find user
    const user = await User.findById(userId);
    if (!user) {
      logger.warn(`User not found: ${userId}`);
      return responseHelper.sendError(req, res, 'User not found', 'Not Found', 404);
    }

    // Check if user is trying to change username and if it's already taken
    if (username && username !== user.username) {
      const existingUser = await User.findOne({ username, _id: { $ne: userId } });
      if (existingUser) {
        logger.warn(`Username already taken: ${username}`);
        return responseHelper.sendError(req, res, 'Username already taken', 'Conflict', 409);
      }
      user.username = username;
    }

    // Check if user is trying to change email and if it's already taken
    if (email && email !== user.email) {
      const existingUser = await User.findOne({ email: email.toLowerCase(), _id: { $ne: userId } });
      if (existingUser) {
        logger.warn(`Email already taken: ${email}`);
        return responseHelper.sendError(req, res, 'Email already taken', 'Conflict', 409);
      }
      user.email = email.toLowerCase();
      user.emailVerified = false; // Reset email verification if email changed
    }

    // Update additional profile fields if provided
    if (fullName !== undefined) user.fullName = fullName || null;
    if (phone !== undefined) user.phone = phone || null;
    if (bio !== undefined) user.bio = bio || null;
    if (dateOfBirth !== undefined) user.dateOfBirth = dateOfBirth || null;
    if (gender !== undefined) user.gender = gender || null; // Convert empty string to null
    if (nationality !== undefined) user.nationality = nationality || null;
    if (passportNumber !== undefined) user.passportNumber = passportNumber || null;
    
    // Update emergency contact if provided
    if (emergencyContact) {
      user.emergencyContact = {
        name: emergencyContact.name || null,
        phone: emergencyContact.phone || null,
        relationship: emergencyContact.relationship || null
      };
    }

    // Update preferences if provided
    if (preferences) {
      user.preferences = {
        budget: preferences.budget || null, // Convert empty string to null
        accommodation: preferences.accommodation || null, // Convert empty string to null
        dietary: preferences.dietary || null,
        interests: preferences.interests || []
      };
    }

    // Save updated user
    await user.save();

    logger.info(`✅ Profile updated successfully for user: ${userId}`);

    // Format response
    const profileData = {
      id: user._id,
      username: user.username,
      email: user.email,
      fullName: user.fullName || user.username,
      phone: user.phone || null,
      avatar: user.avatar,
      role: user.role,
      status: user.status,
      isActive: user.isActive,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified || false,
      platform: user.platform,
      memberSince: user.createdAt,
      verified: user.emailVerified,
      bio: user.bio || null,
      dateOfBirth: user.dateOfBirth || null,
      gender: user.gender || null,
      nationality: user.nationality || null,
      passportNumber: user.passportNumber || null,
      emergencyContact: user.emergencyContact || {
        name: null,
        phone: null,
        relationship: null
      },
      preferences: user.preferences || {
        budget: null,
        accommodation: null,
        dietary: null,
        interests: []
      },
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    };

    logger.info(`Profile updated successfully for user: ${userId}`);
    return responseHelper.sendResponse(req, res, profileData, 'Profile updated successfully', 200);

  } catch (error) {
    logger.error('❌ Error updating profile:', error);
    logger.error('Error stack:', error.stack);
    logger.error('Error details:', {
      name: error.name,
      message: error.message,
      code: error.code
    });
    return responseHelper.sendError(req, res, 'Failed to update profile', 'Server Error', 500);
  }
};

/**
 * Get account status
 * @route GET /profile/status
 * @access Private
 */
const getAccountStatus = async (req, res) => {
  try {
    const userId = req.user.userId;
    logger.info(`Fetching account status for user: ${userId}`);

    const user = await User.findById(userId).select('status isActive emailVerified');

    if (!user) {
      logger.warn(`User not found: ${userId}`);
      return responseHelper.sendError(req, res, 'User not found', 'Not Found', 404);
    }

    const statusData = {
      status: user.status,
      isActive: user.isActive,
      emailVerified: user.emailVerified,
    };

    logger.info(`Account status fetched for user: ${userId}`);
    return responseHelper.sendResponse(req, res, statusData, 'Account status fetched successfully', 200);

  } catch (error) {
    logger.error('Error fetching account status:', error);
    return responseHelper.sendError(req, res, 'Failed to fetch account status', 'Server Error', 500);
  }
};

/**
 * Toggle account status (active/inactive)
 * @route PUT /profile/account-status
 * @access Private
 */
const toggleAccountStatus = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { isActive } = req.body;

    logger.info(`🔄 Toggling account status for user: ${userId} to ${isActive}`);

    // Validate input
    if (typeof isActive !== 'boolean') {
      return responseHelper.sendError(req, res, 'isActive must be a boolean value', 'Bad Request', 400);
    }

    // Find and update user
    const user = await User.findById(userId);

    if (!user) {
      logger.warn(`User not found: ${userId}`);
      return responseHelper.sendError(req, res, 'User not found', 'Not Found', 404);
    }

    // Update status
    user.isActive = isActive;
    user.status = isActive ? 'active' : 'inactive';
    await user.save();

    logger.info(`✅ Account status updated for user: ${userId} - isActive: ${isActive}`);

    return responseHelper.sendResponse(req, res, {
      isActive: user.isActive,
      status: user.status,
      message: isActive ? 'Account activated successfully' : 'Account deactivated successfully'
    }, 'Account status updated successfully', 200);

  } catch (error) {
    logger.error('Error toggling account status:', error);
    return responseHelper.sendError(req, res, 'Failed to update account status', 'Server Error', 500);
  }
};

/**
 * Delete account (soft delete - deactivates account)
 * @route DELETE /profile/delete-account
 * @access Private
 */
const deleteAccount = async (req, res) => {
  try {
    const userId = req.user.userId;
    const { password, confirmation } = req.body;

    logger.info(`🗑️  Account deletion requested for user: ${userId}`);

    // Validate confirmation
    if (confirmation !== 'DELETE MY ACCOUNT') {
      return responseHelper.sendError(
        req, 
        res, 
        'Please type "DELETE MY ACCOUNT" to confirm account deletion', 
        'Bad Request', 
        400
      );
    }

    // Find user
    const user = await User.findById(userId);

    if (!user) {
      logger.warn(`User not found: ${userId}`);
      return responseHelper.sendError(req, res, 'User not found', 'Not Found', 404);
    }

    // Verify password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      logger.warn(`Invalid password for account deletion: ${userId}`);
      return responseHelper.sendError(req, res, 'Invalid password', 'Unauthorized', 401);
    }

    // Soft delete: Deactivate account instead of deleting
    user.isActive = false;
    user.status = 'deleted';
    user.emailVerified = false;
    user.phoneVerified = false;
    
    // Clear refresh tokens
    user.refreshTokens = [];
    
    // Add deletion timestamp
    user.deletedAt = new Date();
    
    // Optionally anonymize personal data
    // user.email = `deleted_${userId}@deleted.com`;
    // user.phone = null;
    // user.avatar = null;
    // user.bio = null;
    
    await user.save();

    logger.info(`✅ Account deleted (soft delete) for user: ${userId}`);

    return responseHelper.sendResponse(req, res, {
      message: 'Your account has been successfully deleted. You can no longer access your account.',
      deletedAt: user.deletedAt
    }, 'Account deleted successfully', 200);

  } catch (error) {
    logger.error('Error deleting account:', error);
    return responseHelper.sendError(req, res, 'Failed to delete account', 'Server Error', 500);
  }
};

module.exports = {
  getProfile,
  updateProfile,
  getAccountStatus,
  toggleAccountStatus,
  deleteAccount,
};
