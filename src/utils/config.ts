import Joi from 'joi';

export default () => ({
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV,
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    accessExpiry: parseInt(process.env.JWT_ACCESS_EXPIRY) || 3600, // 1 hour
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    refreshExpiry: parseInt(process.env.JWT_REFRESH_EXPIRY) || 2592000, // 30 days
  },
  session: {
    expiry: parseInt(process.env.SESSION_EXPIRY) || 86400000, // 24 hours
  },
  security: {
    registration: {
      autoLogin: process.env.REGISTRATION_AUTO_LOGIN === 'true',
    },
    password: {
      bcryptRounds: parseInt(process.env.PASSWORD_BCRYPT_ROUNDS) || 12,
      history: parseInt(process.env.PASSWORD_HISTORY_LIMIT) || 5,
      checkCompromised: process.env.PASSWORD_CHECK_COMPROMISED === 'true',
    },
    rateLimit: {
      register: {
        attempts: parseInt(process.env.REGISTER_RATE_LIMIT_ATTEMPTS) || 5,
        timeframe:
          parseInt(process.env.REGISTER_RATE_LIMIT_TIMEFRAME) || 300000,
      },
      login: {
        attempts: parseInt(process.env.LOGIN_RATE_LIMIT_ATTEMPTS) || 5,
        timeframe: parseInt(process.env.LOGIN_RATE_LIMIT_TIMEFRAME) || 300000,
      },
    },
    mfa: {
      tokenExpiry: parseInt(process.env.MFA_TOKEN_EXPIRY) || 300000, // 5 minutes
    },
    email: {
      verification: {
        expiryHours: parseInt(process.env.VERIFICATION_EXPIRY_HOURS),
      },
    },
    maxFailedAttempts: parseInt(process.env.MAX_FAILED_ATTEMPTS) || 5,
    suspiciousThreshold: parseInt(process.env.SUSPICIOUS_THRESHOLD) || 3,
    lockoutDuration: parseInt(process.env.LOCKOUT_DURATION) || 1800000, // 30 minutes
  },
});

export const validationSchema = Joi.object({
  // Basic configuration
  PORT: Joi.number().port().default(3000),
  NODE_ENV: Joi.string()
    .valid('local', 'development', 'staging', 'production', 'test')
    .required(),

  // Database
  DATABASE_URL: Joi.string().required(),

  // Security configuration
  REGISTRATION_AUTO_LOGIN: Joi.boolean().default(false),
  PASSWORD_BCRYPT_ROUNDS: Joi.number().min(10).max(20).default(12),
  PASSWORD_HISTORY_LIMIT: Joi.number().min(1).default(5),
  PASSWORD_CHECK_COMPROMISED: Joi.boolean().default(true),

  // Rate limiting
  LOGIN_RATE_LIMIT_ATTEMPTS: Joi.number().min(1).default(5),
  LOGIN_RATE_LIMIT_TIMEFRAME: Joi.number().min(60000).default(300000),
  REGISTER_RATE_LIMIT_ATTEMPTS: Joi.number().min(1).default(5),
  REGISTER_RATE_LIMIT_TIMEFRAME: Joi.number().min(60000).default(300000),

  // JWT Configuration
  JWT_ACCESS_SECRET: Joi.string().required(),
  JWT_REFRESH_SECRET: Joi.string().required(),
  JWT_ACCESS_EXPIRY: Joi.number().default(3600),
  JWT_REFRESH_EXPIRY: Joi.number().default(2592000),

  // Session Management
  SESSION_EXPIRY: Joi.number().default(86400000),

  // Security thresholds
  MAX_FAILED_ATTEMPTS: Joi.number().min(1).default(5),
  SUSPICIOUS_THRESHOLD: Joi.number().min(1).default(3),
  LOCKOUT_DURATION: Joi.number().min(30000).default(1800000),
  VERIFICATION_EXPIRY_HOURS: Joi.number().default(24),

  // MFA
  MFA_TOKEN_EXPIRY: Joi.number().default(300000),
});
