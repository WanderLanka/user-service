require('dotenv').config();
const app = require('./app');
const config = require('./config');
const { connectDB } = require('./config/database');
const { logger } = require('./utils');

// Start server
const startServer = async () => {
  try {
    // Connect to database
    await connectDB();
    
    // Start HTTP server
    const server = app.listen(config.port, '0.0.0.0', () => {
      logger.info(`🔐 Auth service running on port ${config.port}`);
      logger.info(`🌐 Health check: http://localhost:${config.port}/health`);
      logger.info(`📱 Mobile API: http://localhost:${config.port}/api/auth/*`);
      logger.info(`🌐 Web API: http://localhost:${config.port}/*`);
    });

    // Graceful shutdown
    process.on('SIGTERM', () => {
      logger.info('SIGTERM received. Shutting down gracefully...');
      server.close(() => {
        logger.info('Process terminated');
        process.exit(0);
      });
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught Exception:', error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

startServer();
