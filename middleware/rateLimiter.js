const rateLimit = require('express-rate-limit');
const config = require('../config');

const authLimiter = rateLimit({
  windowMs: config.rateLimiting.windowMs,
  max: config.rateLimiting.max,
  message: config.rateLimiting.message,
  standardHeaders: true,
  legacyHeaders: false,
});

module.exports = authLimiter;
