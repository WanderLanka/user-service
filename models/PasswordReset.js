const mongoose = require('mongoose');

const passwordResetSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    trim: true
  },
  otp: {
    type: String,
    required: true,
    length: 6
  },
  expiresAt: {
    type: Date,
    required: true,
    default: () => new Date(Date.now() + 15 * 60 * 1000) // 15 minutes from now
  },
  attempts: {
    type: Number,
    default: 0,
    max: 3
  },
  isUsed: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

// Index for efficient queries
passwordResetSchema.index({ email: 1, createdAt: -1 });
passwordResetSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // TTL index

// Static method to find valid OTP
passwordResetSchema.statics.findValidOTP = function(email, otp) {
  return this.findOne({
    email: email.toLowerCase(),
    otp,
    isUsed: false,
    expiresAt: { $gt: new Date() },
    attempts: { $lt: 3 }
  });
};

// Static method to mark OTP as used
passwordResetSchema.statics.markAsUsed = function(email, otp) {
  return this.updateOne(
    { email: email.toLowerCase(), otp, isUsed: false },
    { isUsed: true }
  );
};

// Static method to increment attempts
passwordResetSchema.statics.incrementAttempts = function(email, otp) {
  return this.updateOne(
    { email: email.toLowerCase(), otp },
    { $inc: { attempts: 1 } }
  );
};

// Static method to cleanup expired OTPs
passwordResetSchema.statics.cleanupExpired = function() {
  return this.deleteMany({
    $or: [
      { expiresAt: { $lt: new Date() } },
      { attempts: { $gte: 3 } }
    ]
  });
};

const PasswordReset = mongoose.model('PasswordReset', passwordResetSchema);

module.exports = PasswordReset;
