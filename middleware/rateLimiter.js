const rateLimit = require('express-rate-limit');
const config = require('../config');

const authLimiter = rateLimit({
  windowMs: config.rateLimiting.windowMs,
  max: config.rateLimiting.max,
  message: config.rateLimiting.message,
  standardHeaders: true,
  legacyHeaders: false,
  // Skip rate limiting for localhost in development
  skip: (req) => {
    const isDevelopment = process.env.NODE_ENV !== 'production';
    const isLocalhost = req.ip === '127.0.0.1' || 
                        req.ip === '::1' || 
                        req.ip === '::ffff:127.0.0.1';
    return isDevelopment && isLocalhost;
  },
  // Custom key generator to include path for better isolation
  keyGenerator: (req) => {
    return `${req.ip}:${req.path}`;
  },
});

module.exports = authLimiter;
