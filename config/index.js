const config = {
  port: process.env.PORT || 3001,
  jwtSecret: process.env.JWT_SECRET || 'fallback-secret-key',
  accessTokenExpiry: '24h',
  refreshTokenExpiry: '7d',
  saltRounds: 12,
  corsOrigins: [
    'http://localhost:5173',
    'http://192.168.8.159:8081',
    'exp://192.168.8.159:8081',
    'http://192.168.8.142:8081',
    'exp://192.168.8.142:8081'
  ],
  rateLimiting: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: process.env.NODE_ENV === 'production' ? 10 : 1000, // 10 for prod, 1000 for dev
    message: {
      error: 'Too many authentication attempts, please try again later.',
    }
  }
};

module.exports = config;
