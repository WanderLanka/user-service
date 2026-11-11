require('dotenv').config();
const app = require('./app');
const config = require('./config');
const { connectDB } = require('./config/database');
const { start } = require('./runtime');

start(app, { connect: connectDB, port: config.port }).catch(error => {
  console.error('Service startup failed:', error.message);
  process.exitCode = 1;
});
