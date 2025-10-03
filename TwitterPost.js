const mongoose = require('mongoose');

const twitterMediaSchema = new mongoose.Schema({
  mediaKey: { type: String, default: '' },
  type: { type: String, enum: ['photo', 'video', 'animated_gif'], default: 'photo' },
  url: { type: String, default: '' },
  previewImageUrl: { type: String, default: '' }
}, { _id: false });

const twitterPostSchema = new mongoose.Schema({
  tweetId: { type: String, required: true, unique: true },
  text: { type: String, default: '' },
  createdTime: { type: Date },
  likeCount: { type: Number, default: 0 },
  retweetCount: { type: Number, default: 0 },
  replyCount: { type: Number, default: 0 },
  quoteCount: { type: Number, default: 0 },
  media: { type: [twitterMediaSchema], default: [] },
  hashtags: { type: [String], default: [] },
  mentions: { type: [String], default: [] },
  permalink: { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('TwitterPost', twitterPostSchema);
