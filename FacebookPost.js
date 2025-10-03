const mongoose = require('mongoose');

const facebookPostSchema = new mongoose.Schema({
  postId: { type: String, required: true, unique: true },
  message: { type: String, default: '' },
  story: { type: String, default: '' },
  fullPicture: { type: String, default: '' },
  permalink: { type: String, default: '' },
  createdTime: { type: Date },
  type: { type: String, enum: ['link', 'status', 'photo', 'video', 'offer'] },
  likes: { type: Number, default: 0 },
  comments: { type: Number, default: 0 },
  shares: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('FacebookPost', facebookPostSchema);
