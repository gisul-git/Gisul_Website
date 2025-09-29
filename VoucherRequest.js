const mongoose = require('mongoose');

const voucherRequestSchema = new mongoose.Schema({
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
  jobRole: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 100
  },
  organization: {
    type: String,
    required: true,
    trim: true,
    minlength: 2,
    maxlength: 200
  },
  numberOfWatchers: {
    type: Number,
    required: true,
    min: 1,
    max: 10000
  },
  submittedAt: {
    type: Date,
    default: Date.now
  }
});

module.exports = mongoose.model('VoucherRequest', voucherRequestSchema);
