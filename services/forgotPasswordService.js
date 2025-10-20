const User = require('../models/User');
const PasswordReset = require('../models/PasswordReset');
const TokenService = require('./tokenService');
const EmailService = require('./emailService');
const { logger } = require('../utils');

class ForgotPasswordService {
  
  /**
   * Generate a 6-digit OTP
   */
  static generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
  }

  /**
   * Request password reset - send OTP to email
   */
  static async requestPasswordReset(req) {
    const { email } = req.body;
    
    try {
      // Find user by email
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        // Don't reveal if email exists or not for security
        return {
          data: {},
          message: 'If the email exists in our system, password reset instructions have been sent.',
          statusCode: 200
        };
      }

      // Check if user account is active
      if (user.status === 'suspended') {
        const error = new Error('Account is suspended. Please contact support.');
        error.statusCode = 403;
        throw error;
      }

      if (user.status === 'rejected') {
        const error = new Error('Account has been rejected. Please contact support.');
        error.statusCode = 403;
        throw error;
      }

      // Generate OTP
      const otp = this.generateOTP();
      
      // Store OTP in database with expiration
      await PasswordReset.create({
        email: email.toLowerCase(),
        otp,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 minutes
        attempts: 0,
        isUsed: false
      });

      // Send email with OTP
      try {
        await EmailService.sendPasswordResetEmail(email, otp, user.username);
        logger.info('Password reset OTP sent', { email, userId: user._id });
      } catch (emailError) {
        console.error('❌ Failed to send password reset email:', emailError);
        // Don't fail the request if email fails - log it
        logger.error('Password reset email failed', { email, error: emailError.message });
      }

      return {
        data: {},
        message: 'If the email exists in our system, password reset instructions have been sent.',
        statusCode: 200
      };

    } catch (error) {
      logger.error('Password reset request failed', { email, error: error.message });
      throw error;
    }
  }

  /**
   * Verify OTP for password reset
   */
  static async verifyPasswordResetOTP(req) {
    const { email, otp } = req.body;
    
    try {
      // Find valid OTP
      const passwordReset = await PasswordReset.findValidOTP(email.toLowerCase(), otp);
      
      if (!passwordReset) {
        // Increment attempts for any existing record
        await PasswordReset.incrementAttempts(email.toLowerCase(), otp);
        
        const error = new Error('Invalid or expired OTP. Please check your email and try again.');
        error.statusCode = 400;
        throw error;
      }

      // OTP is valid - return success
      logger.info('Password reset OTP verified', { email });
      
      return {
        data: {
          verified: true,
          message: 'OTP verified successfully'
        },
        message: 'OTP verified successfully',
        statusCode: 200
      };

    } catch (error) {
      logger.error('OTP verification failed', { email, error: error.message });
      throw error;
    }
  }

  /**
   * Reset password with new password
   */
  static async resetPassword(req) {
    const { email, otp, newPassword } = req.body;
    
    try {
      // Find valid OTP
      const passwordReset = await PasswordReset.findValidOTP(email.toLowerCase(), otp);
      
      if (!passwordReset) {
        // Increment attempts for any existing record
        await PasswordReset.incrementAttempts(email.toLowerCase(), otp);
        
        const error = new Error('Invalid or expired OTP. Please request a new password reset.');
        error.statusCode = 400;
        throw error;
      }

      // Find user
      const user = await User.findOne({ email: email.toLowerCase() });
      if (!user) {
        const error = new Error('User not found');
        error.statusCode = 404;
        throw error;
      }

      // Check if user account is active
      if (user.status === 'suspended') {
        const error = new Error('Account is suspended. Please contact support.');
        error.statusCode = 403;
        throw error;
      }

      if (user.status === 'rejected') {
        const error = new Error('Account has been rejected. Please contact support.');
        error.statusCode = 403;
        throw error;
      }

      // Hash new password
      const hashedPassword = await TokenService.hashPassword(newPassword);
      
      // Update user password
      user.password = hashedPassword;
      user.updatedAt = new Date();
      await user.save();

      // Mark OTP as used
      await PasswordReset.markAsUsed(email.toLowerCase(), otp);

      // Invalidate all existing refresh tokens for security
      user.refreshTokens = [];
      await user.save();

      // Send success email
      try {
        await EmailService.sendPasswordResetSuccessEmail(email, user.username);
        logger.info('Password reset success email sent', { email, userId: user._id });
      } catch (emailError) {
        console.error('❌ Failed to send password reset success email:', emailError);
        // Don't fail the request if email fails
        logger.error('Password reset success email failed', { email, error: emailError.message });
      }

      logger.info('Password reset completed', { email, userId: user._id });
      
      return {
        data: {},
        message: 'Password reset successfully. Please log in with your new password.',
        statusCode: 200
      };

    } catch (error) {
      logger.error('Password reset failed', { email, error: error.message });
      throw error;
    }
  }

  /**
   * Cleanup expired OTPs - maintenance function
   */
  static async cleanupExpiredOTPs() {
    try {
      const result = await PasswordReset.cleanupExpired();
      logger.info('Expired OTPs cleaned up', { deletedCount: result.deletedCount });
      return result;
    } catch (error) {
      logger.error('Failed to cleanup expired OTPs', { error: error.message });
      throw error;
    }
  }

  /**
   * Get password reset statistics - for admin/monitoring
   */
  static async getPasswordResetStats() {
    try {
      const totalRequests = await PasswordReset.countDocuments();
      const usedOTPs = await PasswordReset.countDocuments({ isUsed: true });
      const expiredOTPs = await PasswordReset.countDocuments({ 
        $or: [
          { expiresAt: { $lt: new Date() } },
          { attempts: { $gte: 3 } }
        ]
      });
      const activeOTPs = await PasswordReset.countDocuments({ 
        isUsed: false, 
        expiresAt: { $gt: new Date() },
        attempts: { $lt: 3 }
      });

      return {
        totalRequests,
        usedOTPs,
        expiredOTPs,
        activeOTPs
      };
    } catch (error) {
      logger.error('Failed to get password reset stats', { error: error.message });
      throw error;
    }
  }
}

module.exports = ForgotPasswordService;
