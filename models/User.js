const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  role: {
    type: String,
    enum: ['Admin', 'Doctor'],
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true
  },
  mobile: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  // Doctor specific fields
  name: {
    type: String,
    required: function() { return this.role === 'Doctor'; }
  },
  address: {
    type: String,
    required: function() { return this.role === 'Doctor'; }
  },
  clinicHospitalName: {
    type: String,
    required: function() { return this.role === 'Doctor'; }
  },
  qualification: {
    type: String,
    required: function() { return this.role === 'Doctor'; }
  },
  registrationNo: {
    type: String,
    required: function() { return this.role === 'Doctor'; }
  },
  profilePic: {
    type: String, // file path or URL
    required: true
  },
  logoPic: {
    type: String, // file path or URL
    required: function() { return this.role === 'Doctor'; }
  },
  status: {
    type: String,
    enum: ['Active', 'Inactive'],
    default: 'Active'
  }
}, { timestamps: true });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

module.exports = mongoose.model('User', userSchema);