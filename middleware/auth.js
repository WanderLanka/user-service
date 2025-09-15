const TokenService = require('../services/tokenService');

const verifyToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }
  try {
    const decoded = TokenService.verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    res.status(400).json({ error: 'Invalid token' });
  }
};

const verifyMobileToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: 'Access denied',
      error: 'No token provided'
    });
  }
  try {
    const decoded = TokenService.verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Mobile token verification error:', err);
    res.status(401).json({ 
      success: false,
      message: 'Invalid token',
      error: 'Token verification failed'
    });
  }
};

// Unified token verification middleware that detects platform
const verifyUnifiedToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    const platform = req.headers['x-platform'] || 'web';
    if (platform === 'mobile') {
      return res.status(401).json({ 
        success: false,
        message: 'Access denied',
        error: 'No token provided'
      });
    } else {
      return res.status(401).json({ error: 'Access denied. No token provided.' });
    }
  }
  
  try {
    const decoded = TokenService.verifyToken(token);
    req.user = decoded;
    next();
  } catch (err) {
    console.error('Token verification error:', err);
    const platform = req.headers['x-platform'] || 'web';
    
    if (platform === 'mobile') {
      res.status(401).json({ 
        success: false,
        message: 'Invalid token',
        error: 'Token verification failed'
      });
    } else {
      res.status(400).json({ error: 'Invalid token' });
    }
  }
};

module.exports = { verifyToken, verifyMobileToken, verifyUnifiedToken };
