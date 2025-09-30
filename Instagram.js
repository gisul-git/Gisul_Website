const mongoose = require('mongoose');

const instagramChildSchema = new mongoose.Schema({
  mediaType: { type: String, enum: ['IMAGE', 'VIDEO', 'CAROUSEL_ALBUM'], default: undefined },
  mediaUrl: { type: String, default: '' }
}, { _id: false });

const instagramPostSchema = new mongoose.Schema({
  postId: { type: String, required: true, unique: true },
  caption: { type: String, default: '' },
  mediaType: { type: String, enum: ['IMAGE', 'VIDEO', 'CAROUSEL_ALBUM'] },
  mediaUrl: { type: String, default: '' },
  permalink: { type: String, default: '' },
  timestamp: { type: Date },
  likeCount: { type: Number, default: 0 },
  commentsCount: { type: Number, default: 0 },
  thumbnail: { type: String, default: '' },
  children: { type: [instagramChildSchema], default: [] },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('InstagramPost', instagramPostSchema);
