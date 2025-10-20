const express = require('express');
const cors = require('cors');
const path = require('path');
const config = require('./config');
const { logger } = require('./utils');
const authRoutes = require('./routes/authRoutes');
const profileRoutes = require('./routes/profileRoutes');

const app = express();

// Middleware
app.use(cors({
  origin: config.corsOrigins,
  credentials: true
}));

app.use(express.json());

// Serve uploaded documents statically (e.g., /uploads/docs/<file>)
app.use('/uploads', express.static(path.join(process.cwd(), 'uploads')));

// Request logging middleware
app.use((req, res, next) => {
  logger.request(req);
  next();
  // res.status(200).json({ message: 'Intercepted for debugging' }); // DEBUGGING
});

// Routes Handling
app.use('/', authRoutes);
app.use('/', profileRoutes);

// Global error handler
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  const { responseHelper } = require('./utils');
  responseHelper.sendError(req, res, 'Internal server error', 'Server Error', 500);
});

// 404 handler
app.use('*', (req, res) => {
  const { responseHelper } = require('./utils');
  responseHelper.sendError(req, res, 'Route not found', 'Not Found', 404);
});

module.exports = app;
