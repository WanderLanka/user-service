const mongoose = require('mongoose');

// Prefer dedicated user-service DB settings with sensible fallbacks
const uriFromEnv = process.env.USER_MONGO_URI || process.env.MONGO_URI || 'mongodb://localhost:27017';
const dbName = process.env.USER_DB_NAME || 'wanderlanka_user';

const databaseConfig = {
  uri: uriFromEnv,
  dbName,
  options: {
    // Note: Mongoose v7+ ignores deprecated options; keep minimal options here
    dbName,
  }
};

const sanitizeMongoUri = (uri) => {
  try {
    // Mask credentials for both mongodb and mongodb+srv URIs if present
    return uri.replace(/(mongodb(\+srv)?:\/\/)([^:]+):([^@]+)@/i, '$1****:****@');
  } catch {
    return uri;
  }
};

const connectDB = async () => {
  try {
    const { uri, dbName } = databaseConfig;
    console.log('Connecting to MongoDB:', sanitizeMongoUri(uri));
    console.log('Using database:', dbName);

    await mongoose.connect(uri, databaseConfig.options);
    console.log('✅ MongoDB connected successfully');
  } catch (error) {
    console.error('❌ MongoDB connection error:', error.message);
    process.exit(1);
  }
};

module.exports = { connectDB, databaseConfig };
