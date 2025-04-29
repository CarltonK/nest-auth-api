export const DEFAULT_AGENCY_CONFIG = {
  auth: {
    allowRegistration: true,
    requireEmailVerification: true,
    allowPasswordAuth: true,
    allowOauth: true,
    requireMfa: false,
    allowedOauthProviders: ['google'],
    passwordPolicy: {
      minLength: 8,
      requireNumbers: true,
      requireSpecialChars: true,
      requireMixedCase: true,
    },
    sessionPolicy: {
      timeout: 3600,
      renewal: true,
      concurrentSessions: false,
    },
  },
  branding: {
    logoUrl: '',
    primaryColor: '#007bff',
    enableWhiteLabel: false,
  },
  notifications: {
    email: {
      welcomeEnabled: true,
      passwordChangeEnabled: true,
      unusualActivityEnabled: true,
    },
  },
} as const;
