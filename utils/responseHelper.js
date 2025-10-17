
const responseHelper = {
    
  success: (res, data, message = 'Success', statusCode = 200) => {
    return res.status(statusCode).json({
      success: true,
      message,
      data
    });
  },

  error: (res, error, message = 'Error', statusCode = 400) => {
    return res.status(statusCode).json({
      success: false,
      message,
      error: typeof error === 'string' ? error : error.message
    });
  },

  webSuccess: (res, data, message = 'Success', statusCode = 200) => {
    // For login responses, format with separate token field for web compatibility
    if (data.accessToken) {
      return res.status(statusCode).json({
        message,
        token: data.accessToken,
        user: data.user,
        refreshToken: data.refreshToken
      });
    }
    
    // For other responses, spread the data
    return res.status(statusCode).json({
      message,
      ...data
    });
  },

  webError: (res, error, message = 'Error', statusCode = 400) => {
    return res.status(Number(statusCode)).json({
        success: false,
        message,                               // optional general message
        error: typeof error === 'string' ? error : error.message
    });
  },

  // Platform-aware response
  sendResponse: (req, res, data, message = 'Success', statusCode = 200) => {
    const platform = req.headers['x-platform'] || 'web';
    
    if (platform === 'mobile') {
      return responseHelper.success(res, data, message, statusCode);
    } else {
      return responseHelper.webSuccess(res, data, message, statusCode);
    }
  },

  sendError: (req, res, error, message = 'Error', statusCode = 400) => {
    const platform = req.headers['x-platform'] || 'web';
    
    if (platform === 'mobile') {
      return responseHelper.error(res, error, message, statusCode);
    } else {
      return responseHelper.webError(res, error, message,statusCode);
    }
  }
};

module.exports = responseHelper;
