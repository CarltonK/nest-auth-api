import { ConfigService } from '@nestjs/config';

export const createOAuthProviders = (configService: ConfigService) => ({
  google: {
    enabled: configService.get<boolean>('oauth.google.enabled'),
    client_id: configService.get<string>('oauth.google.clientId'),
    redirect_uri: configService.get<string>('oauth.google.redirectUri'),
    auth_endpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    scopes: ['profile', 'email'],
  },
  //   github: {
  //     enabled: configService.get<boolean>('oauth.github.enabled'),
  //     client_id: configService.get<string>('oauth.github.clientId'),
  //     redirect_uri: configService.get<string>('oauth.github.redirectUri'),
  //     auth_endpoint: 'https://github.com/login/oauth/authorize',
  //     scopes: ['user:email'],
  //   },
});
