const mongoose = require('mongoose');

const tempUserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true,
    minlength: 3,
    maxlength: 30
  },
  email: {
    type: String,
    required: true,
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
  enum: ['traveler', 'traveller', 'transport', 'accommodation', 'guide', 'Sysadmin'], // Add both spellings
  default: 'traveler'
},
  status: {
    type: String,
    enum: ['pending', 'approved', 'rejected'],
    default: 'pending'
  },
  platform: {
    type: String,
    enum: ['web', 'mobile'],
    default: 'web'
  },
  emailVerified: {
    type: Boolean,
    default: false
  },
  document: {
    type: String, // file path or cloud URL (e.g. /uploads/docs/abc123.pdf)
    required: function() {
      return this.role === 'transport' || this.role === 'accommodation';
    }
  }
  
}, {
  timestamps: true
});

// Indexes for faster lookups
tempUserSchema.index({ email: 1 });
tempUserSchema.index({ role: 1 });
tempUserSchema.index({ status: 1 });

const TempUser = mongoose.model('TempUser', tempUserSchema);

module.exports = TempUser;
