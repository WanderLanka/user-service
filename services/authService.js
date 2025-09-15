const UserService = require('./userService');
const TokenService = require('./tokenService');
const { validationResult } = require('express-validator');

class AuthService {
  static async register(userData, platform = 'web') {
    // Check if user already exists
    const existingUser = await UserService.findByUsernameOrEmail(userData.username, userData.email);
    if (existingUser) {
      throw new Error(existingUser.username === userData.username ? 'Username already exists' : 'Email already exists');
    }

    // Determine role and status based on platform and role
    let role = userData.role;
    let status = 'active';

    if (platform === 'web') {
      const validWebRoles = ['transport', 'accommodation'];
      if (!validWebRoles.includes(role)) {
        throw new Error('Invalid role for web application');
      }
    } else if (platform === 'mobile') {
      const validMobileRoles = ['tourist', 'guide'];
      if (!validMobileRoles.includes(role)) {
        throw new Error('Role must be either tourist or guide');
      }
      // Map tourist to traveller for mobile app
      if (role === 'tourist') role = 'traveller';
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
    if (platform === 'web' && !['transport', 'accommodation'].includes(user.role)) {
      throw new Error('Invalid credentials');
    } else if (platform === 'mobile' && !['traveller', 'guide'].includes(user.role)) {
      throw new Error('Invalid credentials');
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
