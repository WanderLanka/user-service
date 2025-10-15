const AuthService = require('../services/authService');

const platformHelper = {
  detectPlatform: (req) => {
    return req.headers['x-platform'] || AuthService.detectPlatform(req.get('User-Agent'));
  },

  isMobile: (req) => {
    return platformHelper.detectPlatform(req) === 'mobile';
  },

  isWeb: (req) => {
    return platformHelper.detectPlatform(req) === 'web';
  }
};

module.exports = platformHelper;
