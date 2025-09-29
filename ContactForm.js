const mongoose = require('mongoose');

const contactFormSchema = new mongoose.Schema({
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
  comment: { 
    type: String, 
    required: true, 
    trim: true,
    minlength: 10,
    maxlength: 1000
  },
  submittedAt: { 
    type: Date, 
    default: Date.now 
  },
  status: { 
    type: String, 
    enum: ['new', 'read', 'responded'], 
    default: 'new' 
  }
});

module.exports = mongoose.model('ContactForm', contactFormSchema);
