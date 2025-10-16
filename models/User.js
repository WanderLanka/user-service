const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    required: true,
    enum: ['traveler', 'traveller', 'transport', 'accommodation', 'guide'],   // Mobile uses 'traveler' → mapped to 'traveller'
    default: 'traveler'
  },
  status: {
    type: String,
    enum: ['active', 'pending', 'suspended', 'rejected'],
    default: 'active'
  },
  platform: {
    type: String,
    enum: ['web', 'mobile'],
    default: 'web'
  },
  isActive: {
    type: Boolean,
    default: true
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  avatar: {
    type: String,
    default: null
  },
  guideDetails: {
    firstName: String,
    lastName: String,
    nicNumber: String,
    dateOfBirth: String,
    proofDocument: String,
    approvedAt: {
      type: Date,
      default: null
    },
    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      default: null
    }
  },
  refreshTokens: [{
    token: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: true
});

userSchema.index({ username: 1, email: 1 });
userSchema.index({ refreshTokens: 1 });

const User = mongoose.model('User', userSchema);

module.exports = User;
