const UserService = require('./userService');
const TokenService = require('./tokenService');
const { validationResult } = require('express-validator');

class AuthService {
  static async register(userData, platform = 'web') {
    // Enforce email uniqueness, and auto-generate a unique username if requested one is taken
    const existingByEmail = await UserService.findByUsernameOrEmail(undefined, userData.email);
    if (existingByEmail && existingByEmail.email === userData.email) {
      // Idempotent behavior for mobile guide registration: update existing user if compatible
      if (platform === 'mobile' && userData.role === 'guide') {
        const updated = await UserService.updateUserById(existingByEmail._id, {
          role: 'guide',
          status: 'pending',
          platform: 'mobile',
          isActive: true,
          guideDetails: userData.guideDetails || existingByEmail.guideDetails || null,
        });
        // Upsert in guide-service
        try {
          const GUIDE_URL = process.env.GUIDE_SERVICE_URL || 'http://localhost:3005';
          const payload = {
            userId: updated._id.toString(),
            username: updated.username,
            status: updated.status,
            details: updated.guideDetails || undefined,
          };
          await fetch(`${GUIDE_URL}/guide/insert`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          });
        } catch (e) {
          console.warn('Guide sync failed (idempotent email register):', e?.message || e);
        }

        // For pending guides, don't issue tokens
        return UserService.formatUserResponse(updated, false);
      }
      throw new Error('Email already exists');
    }

    // If requested username exists, generate an available alternative
    let finalUsername = userData.username;
    const existingByUsername = await UserService.findByUsernameOrEmail(userData.username, undefined);
    if (existingByUsername && existingByUsername.username === userData.username) {
      const base = String(userData.username || 'user').toLowerCase().replace(/[^a-z0-9_\.\-]/g, '');
      let attempt = 0;
      let candidate = base;
      // Try a few deterministic suffixes, then random
      while (attempt < 20) {
        // first 5 attempts: -1..-5; then random 4 digits
        candidate = attempt < 5 ? `${base}${attempt + 1}` : `${base}${Math.floor(1000 + Math.random() * 9000)}`;
        // eslint-disable-next-line no-await-in-loop
        const exists = await UserService.findByUsernameOrEmail(candidate, undefined);
        if (!exists) break;
        attempt += 1;
      }
      if (attempt >= 20) {
        throw new Error('Username already exists');
      }
      finalUsername = candidate;
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
      username: finalUsername,
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
