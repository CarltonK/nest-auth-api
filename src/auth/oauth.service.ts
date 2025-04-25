import { Injectable, BadRequestException, Inject } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { HttpService } from '@nestjs/axios';
import { firstValueFrom } from 'rxjs';

@Injectable()
export class OAuthService {
  constructor(
    @Inject(JwtService) private readonly _jwtService: JwtService,
    @Inject(HttpService) private readonly _httpService: HttpService,
    @Inject('OAUTH_PROVIDERS')
    private readonly _oauthProviders: Record<string, any>,
  ) {}

  async verifyOAuthState(
    state: string,
  ): Promise<{ valid: boolean; provider?: string }> {
    try {
      const payload = await this._jwtService.verify(state);
      const { provider } = payload;
      return { valid: true, provider };
    } catch {
      return { valid: false };
    }
  }

  async exchangeCodeForTokens(provider: string, code: string): Promise<any> {
    const config = this._oauthProviders[provider];
    if (!config) {
      throw new BadRequestException({ message: 'Invalid OAuth provider' });
    }

    const params = new URLSearchParams();
    params.append('grant_type', 'authorization_code');
    params.append('client_id', config.client_id);
    params.append('client_secret', config.client_secret);
    params.append('redirect_uri', config.redirect_uri);
    params.append('code', code);

    try {
      const response = await firstValueFrom(
        this._httpService.post(config.token_endpoint, params, {
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        }),
      );
      return response.data;
    } catch {
      throw new BadRequestException({
        message: 'Failed to exchange code for tokens',
      });
    }
  }

  async fetchUserInfo(provider: string, accessToken: string): Promise<any> {
    const config = this._oauthProviders[provider];
    if (!config) {
      throw new BadRequestException({ message: 'Invalid OAuth provider' });
    }

    try {
      const response = await firstValueFrom(
        this._httpService.get(config.userinfo_endpoint, {
          headers: { Authorization: `Bearer ${accessToken}` },
        }),
      );
      return response.data;
    } catch {
      throw new BadRequestException({ message: 'Failed to fetch user info' });
    }
  }
}
