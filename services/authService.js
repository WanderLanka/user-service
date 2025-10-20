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

  static async register(req) {
    // Validate request
    this.validateRequest(req);

    // Detect platform
    const platform = platformHelper.detectPlatform(req);
    console.log('Detected platform:', platform, 'Role received:', req.body.role);

    // Log attempt
    logger.auth('Registration', platform, req.body.username);

    // Check if user already exists
    const existingUser = await UserService.findByUsernameOrEmail(req.body.username, req.body.email);
    if (existingUser) {
      const error = new Error(existingUser.username === req.body.username ? 'Username already exists' : 'Email already exists');
      error.statusCode = 409;
      throw error;
    }

    // Determine role and status based on platform and role
    let role = req.body.role;
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

    // Handle document upload for guides
    let documentPath = null;
    if (req.file) {
      // Document uploaded via multer - saved to uploads/docs/
      documentPath = req.file.path;
      console.log('📄 Document uploaded:', documentPath);
    }

    // Prepare guideDetails with document path if guide role
    let guideDetails = req.body.guideDetails || null;
    if (role === 'guide' && documentPath) {
      guideDetails = {
        ...guideDetails,
        proofDocument: documentPath
      };
    }

    // Create user
    const newUser = await UserService.createUser({
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
      phone: req.body.phone || null,
      role,
      platform,
      status,
      isActive: true,
      emailVerified: false,
      guideDetails
    });

    // Log success
    logger.authSuccess('Registration', platform, req.body.username);

    // If guide registration, sync with guide-service
    if (newUser.role === 'guide') {
      try {
        await this.syncGuideToGuideService(newUser);
        console.log('✅ Guide synced to guide-service:', newUser.username);
      } catch (syncError) {
        console.error('⚠️ Failed to sync guide to guide-service:', syncError.message);
        // Don't fail the registration if sync fails - admin can retry later
      }
    }

    // Registration only returns user data, no tokens
    // Users must login separately to get tokens
    const userData = UserService.formatUserResponse(newUser, false);
    
    // Return structured response based on user role and status
    const message = (newUser.role === 'guide' && newUser.status === 'pending') 
      ? 'Guide registration submitted successfully. Your application will be reviewed by admin.' 
      : 'User registered successfully. Please login to access your account.';
    
    return {
      data: userData,
      message,
      statusCode: 201
    };
  }
 static async redirect(req){
  // Validate request
  this.validateRequest(req);

  // Detect platform
  const platform = platformHelper.detectPlatform(req);
  console.log('Detected platform:', platform, 'Role received:', req.body.role);

  // Log attempt
  logger.auth('Registration', platform, req.body.username);

  // Check if user already exists
  const existingUser = await UserService.findByUsernameOrEmail(req.body.username, req.body.email);
  if (existingUser) {
    const error = new Error(existingUser.username === req.body.username ? 'Username already exists' : 'Email already exists');
    error.statusCode = 409;
    throw error;
  }

  // Determine role and status based on platform and role
  let role = req.body.role;
  let status = 'active';
  
  // FIX: Get document from uploaded file, not req.body
  let document = null;
  if (req.file) {
    // If using multer with single file upload
    document = req.file.path; // or req.file.filename or req.file.location (for cloud storage)
  } else if (req.files && req.files.document) {
    // If using multer with named fields or express-fileupload
    document = req.files.document.path; // adjust based on your setup
  }

  if (platform === 'web') {
    const validWebRoles = ['traveler', 'transport', 'accommodation', 'Sysadmin'];
    if (!validWebRoles.includes(role)) {
      const error = new Error('Invalid role for web application');
      error.statusCode = 400;
      throw error;
    }
    
    // Validate document requirement for transport and accommodation
    if ((role === 'transport' || role === 'accommodation') && !document) {
      const error = new Error('Document is required for transport and accommodation roles');
      error.statusCode = 400;
      throw error;
    }
    
    // Set status to pending for roles requiring approval
    if (role === 'transport' || role === 'accommodation') {
      status = 'pending';
    }
    
  } else if (platform === 'mobile') {
    const validMobileRoles = ['traveler', 'guide'];
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
  const newUser = await UserService.createTempUser({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
    role,
    platform,
    status,
    document,
    isActive: true,
    emailVerified: false,
  });

  console.log('New user created with document:', newUser);

  // Log success
  logger.authSuccess('Registration', platform, req.body.username);

  // Registration only returns user data, no tokens
  const userData = UserService.formatUserResponse(newUser, false);
  
  // Return structured response based on user role and status
  const message = ((newUser.role === 'guide' || newUser.role === 'transport' || newUser.role === 'accommodation') && newUser.status === 'pending') 
    ? 'Registration submitted successfully. Your application will be reviewed by admin.' 
    : 'User registered successfully. Please login to access your account.';
  
  return {
    data: userData,
    message,
    statusCode: 201
  };
}

  static async login(req) {
    // Validate request
    this.validateRequest(req);

    // Detect platform
    const platform = platformHelper.detectPlatform(req);
    
    // Handle both identifier (mobile) and username (web) formats
    const identifier = req.body.identifier || req.body.username;
    
    // Log attempt
    logger.auth('Login', platform, identifier);

    // Find user
    const user = await UserService.findByCredentials(identifier);
    if (!user) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    }

    // Platform-specific role validation
    if (platform === 'web' && !['traveler', 'transport', 'accommodation', 'Sysadmin'].includes(user.role)) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    } else if (platform === 'mobile' && !['traveller', 'guide'].includes(user.role)) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    }

    // Verify password
    const isPasswordValid = await TokenService.comparePassword(req.body.password, user.password);
    if (!isPasswordValid) {
      const error = new Error('Invalid credentials');
      error.statusCode = 401;
      throw error;
    }

    // Check account status
    if (user.role === 'guide' && user.status === 'pending') {
      const error = new Error('Your guide account is still under review. Please wait for admin approval.');
      error.statusCode = 403;
      throw error;
    }

    if (user.status === 'suspended') {
      const error = new Error('Your account has been suspended. Please contact support.');
      error.statusCode = 403;
      throw error;
    }

    if (user.status === 'rejected') {
      const error = new Error('Your guide application has been rejected. Please contact support for more information.');
      error.statusCode = 403;
      throw error;
    }

    // Generate tokens
    const tokens = TokenService.generateTokens(user, platform);
    await UserService.addRefreshToken(user._id, tokens.refreshToken);

    // Log success
    logger.authSuccess('Login', platform, identifier);

    const userData = UserService.formatUserResponse(user, true, tokens);
    
    return {
      data: userData,
      message: 'Login successful',
      statusCode: 200
    };
  }

  static async logout(req) {
    const refreshToken = req.body.refreshToken;
    
    if (refreshToken) {
      await UserService.removeRefreshToken(refreshToken);
    }
    
    return {
      data: {},
      message: 'Logged out successfully',
      statusCode: 200
    };
  }

  static async refreshToken(req) {
    const refreshToken = req.body.refreshToken;
    
    if (!refreshToken) {
      const error = new Error('No refresh token provided');
      error.statusCode = 400;
      throw error;
    }

    // Verify refresh token
    let decoded;
    try {
      decoded = TokenService.verifyToken(refreshToken);
    } catch (err) {
      const error = new Error('Token verification failed');
      error.statusCode = 401;
      throw error;
    }

    // Find user and validate refresh token
    const user = await UserService.findValidRefreshToken(decoded.userId, refreshToken);
    if (!user) {
      const error = new Error('Invalid refresh token');
      error.statusCode = 401;
      throw error;
    }

    // Generate new tokens
    const tokens = TokenService.generateTokens(user, decoded.platform);
    await UserService.addRefreshToken(user._id, tokens.refreshToken);
    await UserService.removeRefreshToken(refreshToken);

    const userData = UserService.formatUserResponse(user, true, tokens);
    
    return {
      data: userData,
      message: 'Token refreshed successfully',
      statusCode: 200
    };
  }
  static async getProfile(req) {
    const userId = req.user.userId;
    
    const user = await UserService.getUserProfile(userId);
    if (!user) {
      const error = new Error('Profile not found');
      error.statusCode = 404;
      throw error;
    }
    
    const userData = UserService.formatUserResponse(user);
    
    return {
      data: { user: userData },
      message: 'Profile retrieved successfully',
      statusCode: 200
    };
  }

  static async verifyToken(req) {
    const userData = {
      valid: true,
      user: {
        userId: req.user.userId,
        username: req.user.username,
        role: req.user.role,
        platform: req.user.platform
      }
    };
    
    return {
      data: userData,
      message: 'Token is valid',
      statusCode: 200
    };
  }

  static async cleanupExpiredTokens(req) {
    const result = await UserService.cleanupExpiredTokens();
    
    return {
      data: { modifiedCount: result.modifiedCount },
      message: 'Token cleanup completed',
      statusCode: 200
    };
  }

  /**
   * Sync guide data to guide-service
   * Called after guide registration or status updates
   */
  static async syncGuideToGuideService(user) {
    try {
      if (!user || user.role !== 'guide') {
        console.warn('⚠️ Attempted to sync non-guide user to guide-service');
        return;
      }

      const GUIDE_SERVICE_URL = process.env.GUIDE_SERVICE_URL || 'http://localhost:3005';
      const guideServiceEndpoint = `${GUIDE_SERVICE_URL}/guide/insert`;
      
      // Prepare payload for guide-service
      const payload = {
        userId: user._id.toString(),
        username: user.username,
        status: user.status || 'pending',
        details: {
          firstName: user.guideDetails?.firstName,
          lastName: user.guideDetails?.lastName,
          bio: user.guideDetails?.bio || '',
          languages: user.guideDetails?.languages || [],
          avatar: user.avatar || null,
          phone: user.phone || null,
        },
        featured: false, // New guides are not featured by default
      };

      console.log('🔄 Syncing guide to guide-service:', {
        endpoint: guideServiceEndpoint,
        userId: payload.userId,
        username: payload.username,
        status: payload.status,
      });

      const response = await fetch(guideServiceEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Guide-service returned ${response.status}: ${errorText}`);
      }

      const result = await response.json();
      console.log('✅ Guide successfully synced to guide-service:', result);
      
      return result;
    } catch (error) {
      console.error('❌ Error syncing guide to guide-service:', error.message);
      throw error;
    }
  }
}

module.exports = AuthService;
