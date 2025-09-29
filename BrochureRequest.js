const mongoose = require('mongoose');

const brochureRequestSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 100
  },
  email: {
    type: String,
    required: true,
    trim: true,
    lowercase: true
  },
  phoneNumber: {
    type: String,
    required: true,
    trim: true
  },
  city: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 100
  },
  educationQualification: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 200
  },
  submittedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('BrochureRequest', brochureRequestSchema);
