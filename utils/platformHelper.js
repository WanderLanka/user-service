const platformHelper = {
  detectPlatform: (req) => {

    //Checking the custome tag of the header
    if (req.headers['x-client-type']) {
      return req.headers['x-client-type'].toLowerCase();
    }

    //Fallback Method to determine the platform
    const ua = req.get('User-Agent') || '';
    return /Mobile|Android|iPhone|iPad/i.test(ua) ? 'mobile' : 'web';
  },

  isMobile: (req) => platformHelper.detectPlatform(req) === 'mobile',
  isWeb: (req) => platformHelper.detectPlatform(req) === 'web',
};

module.exports = platformHelper;
