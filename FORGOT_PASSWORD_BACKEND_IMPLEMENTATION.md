# Forgot Password Backend Implementation

This document describes the complete backend implementation of the "Forgot Password" functionality for the WanderLanka user-service.

## Overview

The backend implementation provides three main endpoints for the forgot password flow:
1. **POST /api/auth/forgot-password** - Request password reset (sends OTP)
2. **POST /api/auth/verify-reset-otp** - Verify OTP
3. **POST /api/auth/reset-password** - Reset password with new password

## Implementation Details

### 1. Dependencies Added

**package.json** - Added nodemailer for email functionality:
```json
{
  "dependencies": {
    "nodemailer": "^6.9.7"
  }
}
```

### 2. Database Models

#### PasswordReset Model (`models/PasswordReset.js`)
```javascript
{
  email: String (required, lowercase, indexed),
  otp: String (required, 6 digits),
  expiresAt: Date (required, 15 minutes TTL),
  attempts: Number (default: 0, max: 3),
  isUsed: Boolean (default: false),
  createdAt: Date (auto),
  updatedAt: Date (auto)
}
```

**Features:**
- TTL index for automatic cleanup of expired OTPs
- Attempt tracking (max 3 attempts per OTP)
- Email indexing for efficient queries
- Static methods for common operations

### 3. Email Service (`services/emailService.js`)

**Features:**
- Gmail SMTP configuration (configurable via environment variables)
- HTML and text email templates
- Password reset email with OTP
- Password reset success confirmation email
- Professional email design with WanderLanka branding
- Deep link support for mobile apps

**Email Templates:**
- **Password Reset Email**: Contains 6-digit OTP, expiration time, security warnings
- **Success Email**: Confirmation that password was reset successfully

### 4. Forgot Password Service (`services/forgotPasswordService.js`)

**Methods:**
- `requestPasswordReset(req)` - Generate and send OTP
- `verifyPasswordResetOTP(req)` - Verify OTP validity
- `resetPassword(req)` - Reset password with new password
- `cleanupExpiredOTPs()` - Maintenance function
- `getPasswordResetStats()` - Statistics for monitoring

**Security Features:**
- 6-digit random OTP generation
- 15-minute OTP expiration
- Maximum 3 attempts per OTP
- Account status validation
- Password hashing with bcrypt
- Refresh token invalidation on password reset

### 5. Validation (`validators/authValidators.js`)

**New Validators:**
- `validateForgotPassword` - Email validation
- `validateVerifyOTP` - Email and 6-digit OTP validation
- `validateResetPassword` - Email, OTP, and strong password validation

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### 6. API Endpoints

#### POST /api/auth/forgot-password
**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "success": true,
  "message": "If the email exists in our system, password reset instructions have been sent.",
  "data": {}
}
```

**Features:**
- Rate limited (same as login)
- Email validation
- Security: Doesn't reveal if email exists
- Sends OTP via email
- Handles suspended/rejected accounts

#### POST /api/auth/verify-reset-otp
**Request:**
```json
{
  "email": "user@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "success": true,
  "message": "OTP verified successfully",
  "data": {
    "verified": true,
    "message": "OTP verified successfully"
  }
}
```

**Features:**
- Rate limited
- OTP format validation
- Expiration checking
- Attempt tracking
- Security: Increments attempts on failure

#### POST /api/auth/reset-password
**Request:**
```json
{
  "email": "user@example.com",
  "otp": "123456",
  "newPassword": "NewSecurePassword123!"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Password reset successfully. Please log in with your new password.",
  "data": {}
}
```

**Features:**
- Rate limited
- Strong password validation
- OTP verification
- Password hashing
- Refresh token invalidation
- Success email notification

### 7. Security Measures

#### Rate Limiting
- All endpoints use the same rate limiter as login
- Prevents brute force attacks
- Configurable via environment variables

#### OTP Security
- 6-digit random OTP
- 15-minute expiration
- Maximum 3 attempts
- Automatic cleanup of expired OTPs
- One-time use (marked as used after successful reset)

#### Account Protection
- Validates account status (active, suspended, rejected)
- Invalidates all refresh tokens on password reset
- Secure password hashing with bcrypt
- No information disclosure about email existence

#### Email Security
- Professional email templates
- Security warnings in emails
- Deep link support for mobile apps
- Success confirmation emails

### 8. Environment Configuration

**Required Environment Variables:**
```bash
# Email Configuration
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# Optional: Guide Service Integration
GUIDE_SERVICE_URL=http://localhost:3005
```

**Gmail Setup:**
1. Enable 2-factor authentication on Gmail
2. Generate an App Password
3. Use the App Password in EMAIL_PASS

### 9. Maintenance Endpoints

#### POST /api/auth/cleanup-expired-otps
**Purpose:** Manual cleanup of expired OTPs
**Response:**
```json
{
  "success": true,
  "message": "Expired OTPs cleaned up successfully",
  "data": {
    "deletedCount": 5
  }
}
```

### 10. Error Handling

**Common Error Responses:**
```json
{
  "success": false,
  "error": "Invalid or expired OTP. Please check your email and try again.",
  "message": "OTP verification failed"
}
```

**Error Types:**
- Validation errors (400)
- Invalid/expired OTP (400)
- Account suspended/rejected (403)
- User not found (404)
- Email service errors (500)

### 11. Logging

**Log Events:**
- Password reset requests
- OTP generation and sending
- OTP verification attempts
- Password reset completions
- Email service errors
- Cleanup operations

**Log Format:**
```javascript
logger.info('Password reset OTP sent', { email, userId });
logger.error('OTP verification failed', { email, error: error.message });
```

### 12. Database Indexes

**PasswordReset Collection:**
```javascript
// Email and creation time index
{ email: 1, createdAt: -1 }

// TTL index for automatic cleanup
{ expiresAt: 1 }, { expireAfterSeconds: 0 }
```

### 13. Integration with Mobile App

**Deep Link Support:**
- Email contains deep link: `wanderlankawebapp://reset-password?email=user@example.com&otp=123456`
- Mobile app can handle deep links to pre-fill reset form
- Seamless user experience across email and mobile app

### 14. Testing Recommendations

#### Unit Tests
- OTP generation and validation
- Email service functionality
- Password validation
- Database operations

#### Integration Tests
- Complete forgot password flow
- Email sending and receiving
- Rate limiting
- Error handling

#### Manual Testing
- Test with valid email addresses
- Test with invalid email addresses
- Test OTP expiration
- Test attempt limits
- Test account status scenarios

### 15. Production Considerations

#### Email Service
- Use production email service (SendGrid, AWS SES, etc.)
- Configure proper SPF/DKIM records
- Monitor email delivery rates
- Set up email bounce handling

#### Monitoring
- Monitor OTP generation rates
- Track email delivery success
- Monitor failed attempts
- Set up alerts for suspicious activity

#### Security
- Regular cleanup of expired OTPs
- Monitor for brute force attempts
- Log security events
- Regular security audits

## Files Created/Modified

### New Files
- `/models/PasswordReset.js` - Password reset OTP model
- `/services/emailService.js` - Email service for sending OTPs
- `/services/forgotPasswordService.js` - Forgot password business logic
- `/FORGOT_PASSWORD_BACKEND_IMPLEMENTATION.md` - This documentation

### Modified Files
- `/package.json` - Added nodemailer dependency
- `/validators/authValidators.js` - Added forgot password validators
- `/controllers/authController.js` - Added forgot password controllers
- `/routes/authRoutes.js` - Added forgot password routes
- `/env.example` - Added email configuration

## API Testing

### Test the Complete Flow

1. **Request Password Reset:**
```bash
curl -X POST http://localhost:3001/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -H "x-client-type: mobile" \
  -d '{"email": "test@example.com"}'
```

2. **Verify OTP:**
```bash
curl -X POST http://localhost:3001/api/auth/verify-reset-otp \
  -H "Content-Type: application/json" \
  -H "x-client-type: mobile" \
  -d '{"email": "test@example.com", "otp": "123456"}'
```

3. **Reset Password:**
```bash
curl -X POST http://localhost:3001/api/auth/reset-password \
  -H "Content-Type: application/json" \
  -H "x-client-type: mobile" \
  -d '{"email": "test@example.com", "otp": "123456", "newPassword": "NewPassword123!"}'
```

## Conclusion

The backend implementation provides a complete, secure, and production-ready forgot password system that integrates seamlessly with the existing WanderLanka user-service architecture. The solution includes proper validation, security measures, email functionality, and comprehensive error handling for a professional user experience.

The implementation is ready for production use with proper email service configuration and monitoring setup.
