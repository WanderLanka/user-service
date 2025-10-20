const User = require('../models/User');
const Tempuser =require('../models/Tempuser');
const TokenService = require('./tokenService');
const mongoose = require('mongoose');

class UserService {
  static async findByCredentials(identifier) {
    return await User.findOne({
      $or: [{ username: identifier }, { email: identifier }],
      isActive: true
    });
  }

  static async findByUsernameOrEmail(username, email) {
    const or = [];
    if (typeof username === 'string' && username) or.push({ username });
    if (typeof email === 'string' && email) or.push({ email });
    if (or.length === 0) return null;
    return await User.findOne({ $or: or });
  }

  static async createUser(userData) {
    const hashedPassword = await TokenService.hashPassword(userData.password);
    
    const user = new User({
      ...userData,
      password: hashedPassword
    });

    return await user.save();
  }

  
  static async createTempUser(tempUserData) {
    const hashedPassword = await TokenService.hashPassword(tempUserData.password);  
    const tempUser = new Tempuser({
      ...tempUserData,
      password: hashedPassword
    });   
    return await tempUser.save();
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
    console.log('🔍 Looking up user profile for userId:', userId);
    console.log('🔍 UserId type:', typeof userId);
    
    // Convert string to ObjectId if needed
    const objectId = mongoose.Types.ObjectId.isValid(userId) 
      ? new mongoose.Types.ObjectId(userId) 
      : userId;
    
    console.log('🔍 Converted to ObjectId:', objectId);
    const user = await User.findById(objectId).select('-password -refreshTokens');
    console.log('🔍 User found:', !!user);
    if (user) {
      console.log('✅ User details:', { id: user._id, username: user.username, role: user.role });
    }
    return user;
  }

  static async updateUserById(userId, update) {
    return await User.findByIdAndUpdate(userId, { $set: update }, { new: true });
  }

  // Optional: call this after admin updates guide status to sync guide-service
  static async notifyGuideServiceSync(user) {
    try {
      if (!user || user.role !== 'guide') return;
      const GUIDE_URL = process.env.GUIDE_SERVICE_URL || 'http://localhost:3005';
      const payload = {
        userId: user._id.toString(),
        username: user.username,
        status: user.status,
        details: user.guideDetails || undefined,
      };
      await fetch(`${GUIDE_URL}/guide/insert`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
    } catch (e) {
      console.warn('Guide sync failed (status update):', e?.message || e);
    }
  }

  // Optional: call this when a guide user is deleted or deactivated
  static async notifyGuideServiceDelete(userId, hard = false) {
    try {
      const GUIDE_URL = process.env.GUIDE_SERVICE_URL || 'http://localhost:3005';
      const qs = hard ? '?hard=true' : '';
      await fetch(`${GUIDE_URL}/guide/delete${qs ? `${qs}&` : '?'}userId=${encodeURIComponent(userId)}`, {
        method: 'DELETE'
      });
    } catch (e) {
      console.warn('Guide delete sync failed:', e?.message || e);
    }
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
