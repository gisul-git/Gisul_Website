const mongoose = require('mongoose');

const youtubeVideoSchema = new mongoose.Schema({
  videoId: { 
    type: String, 
    required: true, 
    unique: true, 
    index: true 
  },
  title: { 
    type: String, 
    required: true, 
    maxlength: 200 
  },
  description: { 
    type: String, 
    default: '', 
    maxlength: 5000 
  },
  thumbnailUrl: { 
    type: String, 
    default: '' 
  },
  thumbnailHdUrl: { 
    type: String, 
    default: '' 
  },
  publishedAt: { 
    type: Date, 
    required: true 
  },
  duration: { 
    type: String, 
    default: '' // ISO 8601 duration format (PT4M13S)
  },
  viewCount: { 
    type: Number, 
    default: 0, 
    min: 0 
  },
  likeCount: { 
    type: Number, 
    default: 0, 
    min: 0 
  },
  commentCount: { 
    type: Number, 
    default: 0, 
    min: 0 
  },
  tags: { 
    type: [String], 
    default: [] 
  },
  categoryId: { 
    type: String, 
    default: '' 
  },
  channelTitle: { 
    type: String, 
    default: '', 
    maxlength: 100 
  },
  embedHtml: { 
    type: String, 
    default: '' 
  },
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

// Indexes for performance
youtubeVideoSchema.index({ publishedAt: -1 }); // For sorting by publish date
youtubeVideoSchema.index({ viewCount: -1 }); // For sorting by popularity
youtubeVideoSchema.index({ likeCount: -1 }); // For sorting by likes
youtubeVideoSchema.index({ channelTitle: 1 }); // For filtering by channel
youtubeVideoSchema.index({ tags: 1 }); // For tag-based searches

// Ensure updatedAt is set on every update
youtubeVideoSchema.pre('save', function(next) {
  this.updatedAt = new Date();
  next();
});

youtubeVideoSchema.pre('findOneAndUpdate', function(next) {
  this.set({ updatedAt: new Date() });
  next();
});

module.exports = mongoose.model('YouTubeVideo', youtubeVideoSchema);
