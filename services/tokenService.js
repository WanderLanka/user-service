const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const config = require('../config');

class TokenService {
  static generateTokens(user, platform = 'web') {
    const payload = {
      userId: user._id,
      username: user.username,
      role: user.role,
      platform
    };

    const accessToken = jwt.sign(payload, config.jwtSecret, { 
      expiresIn: config.accessTokenExpiry 
    });

    const refreshToken = jwt.sign(
      { userId: user._id, type: 'refresh', platform }, 
      config.jwtSecret, 
      { expiresIn: config.refreshTokenExpiry }
    );

    return { accessToken, refreshToken };
  }

  static async hashPassword(password) {
    return await bcrypt.hash(password, config.saltRounds);
  }

  static async comparePassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
  }

  static verifyToken(token) {
    return jwt.verify(token, config.jwtSecret);
  }

  static generateRefreshTokenExpiry() {
    const expiry = new Date();
    expiry.setDate(expiry.getDate() + 7); // 7 days
    return expiry;
  }
}

module.exports = TokenService;
