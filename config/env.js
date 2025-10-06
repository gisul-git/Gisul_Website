// Centralized environment-aware configuration for Dev/QA/UAT/Prod
// APP_ENV must be one of: 'dev' | 'qa' | 'uat' | 'prod'

const DEFAULTS = {
  logLevel: process.env.LOG_LEVEL || 'info',
  session: {
    sameSite: 'None',
    secure: true,
    httpOnly: true,
    maxAgeMs: 24 * 60 * 60 * 1000
  },
  rateLimit: {
    windowMs: 60 * 1000,
    maxRequestsPerWindow: 120
  }
};

const ENV_CONFIG = {
  dev: {
    appEnv: 'dev',
    frontendBaseUrl: process.env.FRONTEND_URL_DEV,
    allowedOrigins: [
      process.env.FRONTEND_URL_DEV
    ],
    mongodbUri: process.env.MONGODB_URI_DEV,
    jwtSecret: process.env.JWT_SECRET_DEV || process.env.JWT_SECRET,
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID_DEV || process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET_DEV || process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI_DEV || process.env.GOOGLE_REDIRECT_URI
    },
    azure: {
      storageConnectionString: process.env.AZURE_STORAGE_CONNECTION_STRING_DEV || process.env.AZURE_STORAGE_CONNECTION_STRING,
      profileContainer: process.env.AZURE_STORAGE_PROFILE_CONTAINER_NAME_DEV || process.env.AZURE_STORAGE_PROFILE_CONTAINER_NAME,
      resumeContainer: process.env.AZURE_STORAGE_CONTAINER_NAME_DEV || process.env.AZURE_STORAGE_CONTAINER_NAME,
      courseContainer: process.env.AZURE_STORAGE_COURSE_CONTAINER_NAME_DEV || process.env.AZURE_STORAGE_COURSE_CONTAINER_NAME
    },
    aws: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID_DEV || process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY_DEV || process.env.AWS_SECRET_ACCESS_KEY,
      sesRegion: process.env.AWS_SES_REGION_DEV || process.env.AWS_SES_REGION,
      sesFromEmail: process.env.AWS_SES_FROM_EMAIL_DEV || process.env.AWS_SES_FROM_EMAIL
    },
    instagram: {
      accessToken: process.env.INSTAGRAM_ACCESS_TOKEN_DEV || process.env.INSTAGRAM_ACCESS_TOKEN,
      businessAccountId: process.env.INSTAGRAM_BUSINESS_ACCOUNT_ID_DEV || process.env.INSTAGRAM_BUSINESS_ACCOUNT_ID
    },
    facebook: {
      appId: process.env.FACEBOOK_APP_ID_DEV || process.env.FACEBOOK_APP_ID,
      pageId: process.env.FACEBOOK_PAGE_ID_DEV || process.env.FACEBOOK_PAGE_ID,
      pageAccessToken: process.env.FACEBOOK_PAGE_ACCESS_TOKEN_DEV || process.env.FACEBOOK_PAGE_ACCESS_TOKEN
    },
    twitter: {
      bearerToken: process.env.TWITTER_BEARER_TOKEN_DEV || process.env.TWITTER_BEARER_TOKEN,
      userId: process.env.TWITTER_USER_ID_DEV || process.env.TWITTER_USER_ID
    },
    youtube: {
      apiKey: process.env.YOUTUBE_API_KEY_DEV || process.env.YOUTUBE_API_KEY,
      channelId: process.env.YOUTUBE_CHANNEL_ID_DEV || process.env.YOUTUBE_CHANNEL_ID
    },    
    logLevel: process.env.LOG_LEVEL_DEV
  },
  qa: {
    appEnv: 'qa',
    frontendBaseUrl: process.env.FRONTEND_URL_QA ,
    allowedOrigins: [
      process.env.FRONTEND_URL_QA 
    ],
    mongodbUri: process.env.MONGODB_URI_QA,
    jwtSecret: process.env.JWT_SECRET_QA || process.env.JWT_SECRET,
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID_QA || process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET_QA || process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI_QA || process.env.GOOGLE_REDIRECT_URI
    },
    azure: {
      storageConnectionString: process.env.AZURE_STORAGE_CONNECTION_STRING_QA || process.env.AZURE_STORAGE_CONNECTION_STRING,
      profileContainer: process.env.AZURE_STORAGE_PROFILE_CONTAINER_NAME_QA || process.env.AZURE_STORAGE_PROFILE_CONTAINER_NAME,
      resumeContainer: process.env.AZURE_STORAGE_CONTAINER_NAME_QA || process.env.AZURE_STORAGE_CONTAINER_NAME,
      courseContainer: process.env.AZURE_STORAGE_COURSE_CONTAINER_NAME_QA || process.env.AZURE_STORAGE_COURSE_CONTAINER_NAME
    },
    aws: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID_QA || process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY_QA || process.env.AWS_SECRET_ACCESS_KEY,
      sesRegion: process.env.AWS_SES_REGION_QA || process.env.AWS_SES_REGION,
      sesFromEmail: process.env.AWS_SES_FROM_EMAIL_QA || process.env.AWS_SES_FROM_EMAIL
    },
    instagram: {
      accessToken: process.env.INSTAGRAM_ACCESS_TOKEN_QA || process.env.INSTAGRAM_ACCESS_TOKEN,
      businessAccountId: process.env.INSTAGRAM_BUSINESS_ACCOUNT_ID_QA || process.env.INSTAGRAM_BUSINESS_ACCOUNT_ID
    },
    facebook: {
      appId: process.env.FACEBOOK_APP_ID_QA || process.env.FACEBOOK_APP_ID,
      pageId: process.env.FACEBOOK_PAGE_ID_QA || process.env.FACEBOOK_PAGE_ID,
      pageAccessToken: process.env.FACEBOOK_PAGE_ACCESS_TOKEN_QA || process.env.FACEBOOK_PAGE_ACCESS_TOKEN
    },
    twitter: {
      bearerToken: process.env.TWITTER_BEARER_TOKEN_QA || process.env.TWITTER_BEARER_TOKEN,
      userId: process.env.TWITTER_USER_ID_QA || process.env.TWITTER_USER_ID
    },
    youtube: {
      apiKey: process.env.YOUTUBE_API_KEY_QA || process.env.YOUTUBE_API_KEY,
      channelId: process.env.YOUTUBE_CHANNEL_ID_QA || process.env.YOUTUBE_CHANNEL_ID
    },    
    logLevel: process.env.LOG_LEVEL_QA
  },
  uat: {
    appEnv: 'uat',
    frontendBaseUrl: process.env.FRONTEND_URL_UAT ,
    allowedOrigins: [
      process.env.FRONTEND_URL_UAT 
    ],
    mongodbUri: process.env.MONGODB_URI_UAT,
    jwtSecret: process.env.JWT_SECRET_UAT || process.env.JWT_SECRET,
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID_UAT || process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET_UAT || process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI_UAT || process.env.GOOGLE_REDIRECT_URI
    },
    azure: {
      storageConnectionString: process.env.AZURE_STORAGE_CONNECTION_STRING_UAT || process.env.AZURE_STORAGE_CONNECTION_STRING,
      profileContainer: process.env.AZURE_STORAGE_PROFILE_CONTAINER_NAME_UAT || process.env.AZURE_STORAGE_PROFILE_CONTAINER_NAME,
      resumeContainer: process.env.AZURE_STORAGE_CONTAINER_NAME_UAT || process.env.AZURE_STORAGE_CONTAINER_NAME,
      courseContainer: process.env.AZURE_STORAGE_COURSE_CONTAINER_NAME_UAT || process.env.AZURE_STORAGE_COURSE_CONTAINER_NAME
    },
    aws: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID_UAT || process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY_UAT || process.env.AWS_SECRET_ACCESS_KEY,
      sesRegion: process.env.AWS_SES_REGION_UAT || process.env.AWS_SES_REGION,
      sesFromEmail: process.env.AWS_SES_FROM_EMAIL_UAT || process.env.AWS_SES_FROM_EMAIL
    },
    instagram: {
      accessToken: process.env.INSTAGRAM_ACCESS_TOKEN_UAT || process.env.INSTAGRAM_ACCESS_TOKEN,
      businessAccountId: process.env.INSTAGRAM_BUSINESS_ACCOUNT_ID_UAT || process.env.INSTAGRAM_BUSINESS_ACCOUNT_ID
    },
    facebook: {
      appId: process.env.FACEBOOK_APP_ID_UAT || process.env.FACEBOOK_APP_ID,
      pageId: process.env.FACEBOOK_PAGE_ID_UAT || process.env.FACEBOOK_PAGE_ID,
      pageAccessToken: process.env.FACEBOOK_PAGE_ACCESS_TOKEN_UAT || process.env.FACEBOOK_PAGE_ACCESS_TOKEN
    },
    twitter: {
      bearerToken: process.env.TWITTER_BEARER_TOKEN_UAT || process.env.TWITTER_BEARER_TOKEN,
      userId: process.env.TWITTER_USER_ID_UAT || process.env.TWITTER_USER_ID
    },
    youtube: {
      apiKey: process.env.YOUTUBE_API_KEY_UAT || process.env.YOUTUBE_API_KEY,
      channelId: process.env.YOUTUBE_CHANNEL_ID_UAT || process.env.YOUTUBE_CHANNEL_ID
    },    
    logLevel: process.env.LOG_LEVEL_UAT || 'info'
  },
  prod: {
    appEnv: 'prod',
    frontendBaseUrl: process.env.FRONTEND_URL_PROD,
    allowedOrigins: [
      process.env.FRONTEND_URL_PROD,
      process.env.FRONTEND_URL_PROD_WWW
    ],
    mongodbUri: process.env.MONGODB_URI || process.env.MONGODB_URI_PROD,
    jwtSecret: process.env.JWT_SECRET,
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      redirectUri: process.env.GOOGLE_REDIRECT_URI
    },
    azure: {
      storageConnectionString: process.env.AZURE_STORAGE_CONNECTION_STRING,
      profileContainer: process.env.AZURE_STORAGE_PROFILE_CONTAINER_NAME,
      resumeContainer: process.env.AZURE_STORAGE_CONTAINER_NAME,
      courseContainer: process.env.AZURE_STORAGE_COURSE_CONTAINER_NAME
    },
    aws: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
      sesRegion: process.env.AWS_SES_REGION,
      sesFromEmail: process.env.AWS_SES_FROM_EMAIL
    },
    instagram: {
      accessToken: process.env.INSTAGRAM_ACCESS_TOKEN,
      businessAccountId: process.env.INSTAGRAM_BUSINESS_ACCOUNT_ID
    },
    facebook: {
      appId: process.env.FACEBOOK_APP_ID,
      pageId: process.env.FACEBOOK_PAGE_ID,
      pageAccessToken: process.env.FACEBOOK_PAGE_ACCESS_TOKEN
    },
    twitter: {
      bearerToken: process.env.TWITTER_BEARER_TOKEN,
      userId: process.env.TWITTER_USER_ID
    },
    youtube: {
      apiKey: process.env.YOUTUBE_API_KEY,
      channelId: process.env.YOUTUBE_CHANNEL_ID
    },
    logLevel: process.env.LOG_LEVEL
  }
};

function getAppEnv() {
  const value = (process.env.APP_ENV || '').toLowerCase();
  if (value === 'dev' || value === 'qa' || value === 'uat' || value === 'prod') return value;
  // Fallback mapping from NODE_ENV
  const nodeEnv = (process.env.NODE_ENV || '').toLowerCase();
  if (nodeEnv === 'production') return 'prod';
  if (nodeEnv === 'test') return 'qa';
  return 'dev';
}

function getConfig() {
  const appEnv = getAppEnv();
  const envCfg = ENV_CONFIG[appEnv];
  return {
    ...DEFAULTS,
    ...envCfg
  };
}

module.exports = {
  getConfig,
  getAppEnv
};


