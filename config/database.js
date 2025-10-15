const mongoose = require('mongoose');

const databaseConfig = {
  uri: process.env.MONGO_URI || 'mongodb://localhost:27017/wanderlanka',
  options: {
    // Remove deprecated options
  }
};

const connectDB = async () => {
  try {
    const mongoUri = databaseConfig.uri;
    console.log('Connecting to MongoDB:', mongoUri.replace(/mongodb\+srv:\/\/[^:]+:[^@]+@/, 'mongodb+srv://****:****@'));
    
    await mongoose.connect(mongoUri, databaseConfig.options);
    console.log('✅ MongoDB connected successfully');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    process.exit(1);
  }
};

module.exports = { connectDB, databaseConfig };
