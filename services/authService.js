const UserService = require('./userService');
const TokenService = require('./tokenService');
const { validationResult } = require('express-validator');
const { platformHelper, logger } = require('../utils');

class AuthService {
    
  static validateRequest(req) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const errorMessages = errors.array().map(error => error.msg);
      throw new Error(errorMessages.join(', '));
    }
  }

  static async register(userData, platform) {
    // Note: validation and platform detection is done in controller
    
    console.log('Detected platform:', platform, 'Role received:', userData.role);

    // Log attempt
    logger.auth('Registration', platform, userData.username);

    // Check if user already exists
    const existingUser = await UserService.findByUsernameOrEmail(userData.username, userData.email);
    if (existingUser) {
      const error = new Error(existingUser.username === userData.username ? 'Username already exists' : 'Email already exists');
      error.statusCode = 409;
      throw error;
    }

    // Determine role and status based on platform and role
    let role = userData.role;
    let status = 'active';

    if (platform === 'web') {
      const validWebRoles = ['traveler', 'transport', 'accommodation', 'Sysadmin'];  // Web: all EXCEPT guide
      if (!validWebRoles.includes(role)) {
        const error = new Error('Invalid role for web application');
        error.statusCode = 400;
        throw error;
      }
    } else if (platform === 'mobile') {
      const validMobileRoles = ['traveler', 'guide'];  // Mobile: ONLY traveler and guide
      if (!validMobileRoles.includes(role)) {
        const error = new Error('Role must be either traveler or guide');
        error.statusCode = 400;
        throw error;
      }
      // For mobile, map traveler to traveller in database
      if (role === 'traveler') role = 'traveller';
      // Guides need admin approval
      if (role === 'guide') status = 'pending';
    }

    // Create user
    const newUser = await UserService.createUser({
      username: userData.username,
      email: userData.email,
      password: userData.password,
      role,
      platform,
      status,
      isActive: true,
      emailVerified: false,
      guideDetails: userData.guideDetails || null
    });

    // If a guide registered, notify guide-service to upsert a Guide record
    if (role === 'guide') {
      try {
        const GUIDE_URL = process.env.GUIDE_SERVICE_URL || 'http://localhost:3005';
        const payload = {
          userId: newUser._id.toString(),
          username: newUser.username,
          status, // likely 'pending' at registration
          details: userData.guideDetails || undefined,
        };
        // Use native fetch to avoid adding a dependency
        // Prefer CRUD insert which is idempotent (upsert by userId)
        await fetch(`${GUIDE_URL}/guide/insert`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload),
        });
      } catch (e) {
        // Log and continue; do not block user registration if guide-service is unavailable
        console.warn('Guide sync failed (registration):', e?.message || e);
      }
    }

    // Generate tokens only for active users
    if (status === 'active') {
      const tokens = TokenService.generateTokens(newUser, platform);
      await UserService.addRefreshToken(newUser._id, tokens.refreshToken);
      return UserService.formatUserResponse(newUser, true, tokens);
    }

    return UserService.formatUserResponse(newUser, false);
  }

  static async login(identifier, password, platform = 'web') {
    // Find user
    const user = await UserService.findByCredentials(identifier);
    if (!user) {
      throw new Error('Invalid credentials');
    }

    // Platform-specific role validation
    if (platform === 'web') {
      // Web allows all roles EXCEPT guide: traveler, transport, accommodation, admin
      if (!['traveler', 'traveller', 'transport', 'accommodation', 'Sysadmin'].includes(user.role)) {
        const error = new Error('Invalid credentials');
        error.statusCode = 401;
        throw error;
      }
    } else if (platform === 'mobile') {
      // Mobile allows ONLY: travelers and guides
      if (!['traveler', 'traveller', 'guide'].includes(user.role)) {
        throw new Error('Invalid credentials');
      }
    }

    // Verify password
    const isPasswordValid = await TokenService.comparePassword(password, user.password);
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    // Check account status
    if (user.role === 'guide' && user.status === 'pending') {
      throw new Error('Your guide account is still under review. Please wait for admin approval.');
    }

    if (user.status === 'suspended') {
      throw new Error('Your account has been suspended. Please contact support.');
    }

    if (user.status === 'rejected') {
      throw new Error('Your guide application has been rejected. Please contact support for more information.');
    }

    // Generate tokens
    const tokens = TokenService.generateTokens(user, platform);
    await UserService.addRefreshToken(user._id, tokens.refreshToken);

    return UserService.formatUserResponse(user, true, tokens);
  }

  static async logout(refreshToken) {
    if (refreshToken) {
      await UserService.removeRefreshToken(refreshToken);
    }
    return { message: 'Logged out successfully' };
  }

  static async refreshToken(refreshToken) {
    if (!refreshToken) {
      throw new Error('No refresh token provided');
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = TokenService.verifyToken(refreshToken);
    } catch (err) {
      throw new Error('Token verification failed');
    }

    // Find user and validate refresh token
    const user = await UserService.findValidRefreshToken(decoded.userId, refreshToken);
    if (!user) {
      throw new Error('Invalid refresh token');
    }

    // Generate new tokens
    const tokens = TokenService.generateTokens(user, decoded.platform);

    // Replace old refresh token with new one
    await UserService.removeRefreshToken(refreshToken);
    await UserService.addRefreshToken(user._id, tokens.refreshToken);

    return UserService.formatUserResponse(user, true, tokens);
  }

  static async getProfile(userId) {
    const user = await UserService.getUserProfile(userId);
    if (!user) {
      throw new Error('Profile not found');
    }
    return UserService.formatUserResponse(user);
  }

  static async cleanupExpiredTokens() {
    const result = await UserService.cleanupExpiredTokens();
    return { modifiedCount: result.modifiedCount };
  }

  static validateRequest(req) {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      throw new Error(errors.array()[0].msg);
    }
  }

  static detectPlatform(userAgent) {
    // Simple platform detection based on User-Agent
    if (userAgent && userAgent.includes('Expo')) {
      return 'mobile';
    }
    return 'web';
  }
}

module.exports = AuthService;
