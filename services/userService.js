const User = require('../models/User');
const TokenService = require('./tokenService');

class UserService {
  static async findByCredentials(identifier) {
    return await User.findOne({
      $or: [{ username: identifier }, { email: identifier }],
      isActive: true
    });
  }

  static async findByUsernameOrEmail(username, email) {
    return await User.findOne({
      $or: [{ username }, { email }]
    });
  }

  static async createUser(userData) {
    const hashedPassword = await TokenService.hashPassword(userData.password);
    
    const user = new User({
      ...userData,
      password: hashedPassword
    });

    return await user.save();
  }

  static async addRefreshToken(userId, refreshToken) {
    const refreshTokenExpiry = TokenService.generateRefreshTokenExpiry();
    
    return await User.updateOne(
      { _id: userId },
      {
        $push: {
          refreshTokens: {
            token: refreshToken,
            expiresAt: refreshTokenExpiry
          }
        }
      }
    );
  }

  static async removeRefreshToken(refreshToken) {
    return await User.updateOne(
      { 'refreshTokens.token': refreshToken },
      { $pull: { refreshTokens: { token: refreshToken } } }
    );
  }

  static async findValidRefreshToken(userId, refreshToken) {
    const user = await User.findById(userId);
    if (!user) return null;

    const tokenExists = user.refreshTokens.some(
      tokenObj => tokenObj.token === refreshToken && tokenObj.expiresAt > new Date()
    );

    return tokenExists ? user : null;
  }

  static async cleanupExpiredTokens() {
    return await User.updateMany(
      {},
      {
        $pull: {
          refreshTokens: {
            expiresAt: { $lt: new Date() }
          }
        }
      }
    );
  }

  static async getUserProfile(userId) {
    return await User.findById(userId).select('-password -refreshTokens');
  }

  static formatUserResponse(user, includeTokens = false, tokens = {}) {
    const userResponse = {
      id: user._id.toString(),
      username: user.username,
      email: user.email,
      role: user.role,
      status: user.status,
      avatar: user.avatar,
      isActive: user.isActive,
      emailVerified: user.emailVerified,
      platform: user.platform,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    };

    if (user.guideDetails) {
      userResponse.guideDetails = user.guideDetails;
    }

    if (includeTokens) {
      return {
        user: userResponse,
        ...tokens
      };
    }

    return userResponse;
  }
}

module.exports = UserService;
