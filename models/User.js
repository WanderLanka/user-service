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
    enum: ['traveler', 'traveller', 'transport', 'accommodation', 'guide'],   //// Change the tourist to traveler here
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
  fullName: {
    type: String,
    trim: true,
    default: null
  },
  phone: {
    type: String,
    trim: true,
    default: null
  },
  phoneVerified: {
    type: Boolean,
    default: false
  },
  bio: {
    type: String,
    maxlength: 500,
    default: null
  },
  dateOfBirth: {
    type: String,
    default: null
  },
  gender: {
    type: String,
    enum: ['Male', 'Female', 'Other', null],
    default: null
  },
  nationality: {
    type: String,
    default: null
  },
  passportNumber: {
    type: String,
    trim: true,
    default: null
  },
  emergencyContact: {
    name: {
      type: String,
      default: null
    },
    phone: {
      type: String,
      default: null
    },
    relationship: {
      type: String,
      default: null
    }
  },
  preferences: {
    budget: {
      type: String,
      enum: ['Budget', 'Mid-range', 'Luxury', null],
      default: null
    },
    accommodation: {
      type: String,
      enum: ['Hotel', 'Hostel', 'Guesthouse', 'Resort', 'Airbnb', null],
      default: null
    },
    dietary: {
      type: String,
      default: null
    },
    interests: [{
      type: String
    }]
  },
  guideDetails: {
    firstName: String,
    lastName: String,
    nicNumber: String,
    dateOfBirth: String,
    bio: String,
    languages: [String],
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
