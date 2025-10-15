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
    return res.status(statusCode).json({
      message,
      ...data
    });
  },

  webError: (res, error, statusCode = 400) => {
    return res.status(statusCode).json({
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
      return responseHelper.webError(res, error, statusCode);
    }
  }
};

module.exports = responseHelper;
