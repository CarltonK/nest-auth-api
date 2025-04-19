import Joi from 'joi';

export default () => ({
  PORT: process.env.PORT || 3000,
  NODE_ENV: process.env.NODE_ENV,
  security: {
    registration: {
      autoLogin: process.env.REGISTRATION_AUTO_LOGIN === 'true',
    },
    password: {
      bcryptRounds: parseInt(process.env.PASSWORD_BCRYPT_ROUNDS) || 12,
      history: parseInt(process.env.PASSWORD_HISTORY_LIMIT) || 5,
      checkCompromised: process.env.PASSWORD_CHECK_COMPROMISED === 'true',
    },
    rateLimiting: {
      register: {
        attempts: parseInt(process.env.REGISTER_RATE_LIMIT_ATTEMPTS) || 5,
        timeframe:
          parseInt(process.env.REGISTER_RATE_LIMIT_TIMEFRAME) || 300000,
      },
    },
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
  REGISTER_RATE_LIMIT_ATTEMPTS: Joi.number().min(1).default(5),
  REGISTER_RATE_LIMIT_TIMEFRAME: Joi.number().min(60000).default(300000),
});
