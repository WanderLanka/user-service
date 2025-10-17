const logger = {
  info: (message, data = {}) => {
    console.log(`${new Date().toISOString()} - INFO: ${message}`, data);
  },

  error: (message, error = {}) => {
    console.error(`${new Date().toISOString()} - ERROR: ${message}`, error);
  },

  warn: (message, data = {}) => {
    console.warn(`${new Date().toISOString()} - WARN: ${message}`, data);
  },

  request: (req) => {
    const { method, path, ip} = req;
    const userAgent = req.get('User-Agent') || 'Unknown';
    console.log(`${new Date().toISOString()} - REQUEST: ${method} ${path} - ${userAgent} - IP: ${ip}`);
    // console.log('Headers:', req.headers);  // DEBUGGING
  },

  auth: (action, platform, identifier) => {
    console.log(`${new Date().toISOString()} - AUTH: ${platform.toUpperCase()} ${action} attempt - ${identifier}`);
  },

  authSuccess: (action, platform, identifier) => {
    console.log(`${new Date().toISOString()} - AUTH SUCCESS: ${platform.toUpperCase()} ${action} successful - ${identifier}`);
  }
};

module.exports = logger;
