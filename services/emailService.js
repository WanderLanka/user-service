const nodemailer = require('nodemailer');
const { logger } = require('../utils');

class EmailService {
  constructor() {
    this.transporter = null;
    this.initializeTransporter();
  }

  initializeTransporter() {
    try {
      // For development, use Gmail SMTP
      // In production, you should use a proper email service like SendGrid, AWS SES, etc.
      this.transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: process.env.EMAIL_USER || 'wanderlanka2025@gmail.com',
          pass: process.env.EMAIL_PASS || 'eohe oaxf sizj xoam' // Use App Password for Gmail
        }
      });

      // Verify transporter configuration
      this.transporter.verify((error, success) => {
        if (error) {
          console.error('❌ Email service configuration error:', error.message);
          logger.error('Email service failed to initialize', error);
        } else {
          console.log('✅ Email service ready to send emails');
          logger.info('Email service initialized successfully');
        }
      });
    } catch (error) {
      console.error('❌ Failed to initialize email service:', error);
      logger.error('Email service initialization failed', error);
    }
  }

  async sendPasswordResetEmail(email, otp, username = 'User') {
    try {
      if (!this.transporter) {
        throw new Error('Email service not initialized');
      }

      // Email credentials are now hardcoded, so we can proceed

      const mailOptions = {
        from: {
          name: 'WanderLanka',
          address: process.env.EMAIL_USER || 'wanderlanka2025@gmail.com'
        },
        to: email,
        subject: 'Reset Your WanderLanka Password',
        html: this.generatePasswordResetHTML(username, otp, email),
        text: this.generatePasswordResetText(username, otp, email)
      };

      const result = await this.transporter.sendMail(mailOptions);
      console.log('✅ Password reset email sent successfully:', result.messageId);
      logger.info('Password reset email sent', { email, messageId: result.messageId });
      
      return {
        success: true,
        messageId: result.messageId
      };
    } catch (error) {
      console.error('❌ Failed to send password reset email:', error);
      logger.error('Password reset email failed', { email, error: error.message });
      throw new Error('Failed to send password reset email');
    }
  }

  generatePasswordResetHTML(username, otp, email) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset Your Password - WanderLanka</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8fafc;
          }
          .container {
            background-color: #ffffff;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          .logo {
            font-size: 28px;
            font-weight: bold;
            color: #059669;
            margin-bottom: 10px;
          }
          .otp-container {
            background-color: #f0f9ff;
            border: 2px solid #059669;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
          }
          .otp-code {
            font-size: 32px;
            font-weight: bold;
            color: #059669;
            letter-spacing: 8px;
            margin: 10px 0;
          }
          .warning {
            background-color: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
          }
          .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
          }
          .button {
            display: inline-block;
            background-color: #059669;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            margin: 10px 0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🌴 WanderLanka</div>
            <h1>Reset Your Password</h1>
          </div>
          
          <p>Hi ${username},</p>
          
          <p>You requested to reset your password for your WanderLanka account. Use the verification code below to reset your password:</p>
          
          <div class="otp-container">
            <p><strong>Your verification code:</strong></p>
            <div class="otp-code">${otp}</div>
            <p><small>This code will expire in 15 minutes</small></p>
          </div>
          
          <div class="warning">
            <strong>⚠️ Security Notice:</strong>
            <ul>
              <li>This code is valid for 15 minutes only</li>
              <li>You can attempt to use this code up to 3 times</li>
              <li>If you didn't request this password reset, please ignore this email</li>
              <li>Never share this code with anyone</li>
            </ul>
          </div>
          
          <p>If you're having trouble with the code, you can also use the deep link below:</p>
          <p><a href="wanderlankawebapp://reset-password?email=${encodeURIComponent(email)}&otp=${otp}" class="button">Reset Password</a></p>
          
          <div class="footer">
            <p>This email was sent by WanderLanka</p>
            <p>If you didn't request this password reset, please contact our support team.</p>
            <p>© 2024 WanderLanka. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generatePasswordResetText(username, otp, email) {
    return `
Reset Your WanderLanka Password

Hi ${username},

You requested to reset your password for your WanderLanka account.

Your verification code: ${otp}

This code will expire in 15 minutes.

Security Notice:
- This code is valid for 15 minutes only
- You can attempt to use this code up to 3 times
- If you didn't request this password reset, please ignore this email
- Never share this code with anyone

If you're having trouble, you can also use this deep link:
wanderlankawebapp://reset-password?email=${encodeURIComponent(email)}&otp=${otp}

This email was sent by WanderLanka
If you didn't request this password reset, please contact our support team.

© 2024 WanderLanka. All rights reserved.
    `;
  }

  async sendPasswordResetSuccessEmail(email, username = 'User') {
    try {
      if (!this.transporter) {
        throw new Error('Email service not initialized');
      }

      // Email credentials are now hardcoded, so we can proceed

      const mailOptions = {
        from: {
          name: 'WanderLanka',
          address: process.env.EMAIL_USER || 'praneeshsuren@gmail.com'
        },
        to: email,
        subject: 'Password Reset Successful - WanderLanka',
        html: this.generatePasswordResetSuccessHTML(username),
        text: this.generatePasswordResetSuccessText(username)
      };

      const result = await this.transporter.sendMail(mailOptions);
      console.log('✅ Password reset success email sent:', result.messageId);
      logger.info('Password reset success email sent', { email, messageId: result.messageId });
      
      return {
        success: true,
        messageId: result.messageId
      };
    } catch (error) {
      console.error('❌ Failed to send password reset success email:', error);
      logger.error('Password reset success email failed', { email, error: error.message });
      // Don't throw error for success email - it's not critical
      return { success: false, error: error.message };
    }
  }

  generatePasswordResetSuccessHTML(username) {
    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset Successful - WanderLanka</title>
        <style>
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8fafc;
          }
          .container {
            background-color: #ffffff;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
          }
          .header {
            text-align: center;
            margin-bottom: 30px;
          }
          .logo {
            font-size: 28px;
            font-weight: bold;
            color: #059669;
            margin-bottom: 10px;
          }
          .success {
            background-color: #dcfce7;
            border: 2px solid #059669;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
          }
          .success-icon {
            font-size: 48px;
            margin-bottom: 10px;
          }
          .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            color: #6b7280;
            font-size: 14px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <div class="logo">🌴 WanderLanka</div>
            <h1>Password Reset Successful</h1>
          </div>
          
          <p>Hi ${username},</p>
          
          <div class="success">
            <div class="success-icon">✅</div>
            <h2>Your password has been successfully reset!</h2>
            <p>You can now log in to your WanderLanka account using your new password.</p>
          </div>
          
          <p>If you didn't make this change, please contact our support team immediately as your account may have been compromised.</p>
          
          <div class="footer">
            <p>This email was sent by WanderLanka</p>
            <p>© 2024 WanderLanka. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `;
  }

  generatePasswordResetSuccessText(username) {
    return `
Password Reset Successful - WanderLanka

Hi ${username},

Your password has been successfully reset!

You can now log in to your WanderLanka account using your new password.

If you didn't make this change, please contact our support team immediately as your account may have been compromised.

This email was sent by WanderLanka
© 2024 WanderLanka. All rights reserved.
    `;
  }
}

module.exports = new EmailService();
