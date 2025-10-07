const mongoose = require('mongoose');

const facebookPostSchema = new mongoose.Schema({
  postId: { type: String, required: true, unique: true, index: true },
  message: { type: String, default: '' },
  story: { type: String, default: '' },
  fullPicture: { type: String, default: '' },
  permalink: { type: String, default: '' },
  createdTime: { type: Date, required: true },
  likes: { type: Number, default: 0, min: 0 },
  comments: { type: Number, default: 0, min: 0 },
  shares: { type: Number, default: 0, min: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  timestamps: true
});

// Index for sorting posts by creation time (improves query performance)
facebookPostSchema.index({ createdTime: -1 });

module.exports = mongoose.model('FacebookPost', facebookPostSchema);