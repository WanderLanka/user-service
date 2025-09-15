const User = require('../models/User');

// Health check
const healthCheck = (req, res) => {
  res.status(200).json({
    status: 'OK',
    message: 'WanderLanka User Service is running',
    timestamp: new Date().toISOString(),
    services: {
      database: User.db && User.db.readyState === 1 ? 'connected' : 'disconnected'
    }
  });
};

module.exports = {
  healthCheck
};
