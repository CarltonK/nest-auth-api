import { Inject, Injectable } from '@nestjs/common';
import { JwtService as NestJwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtService {
  constructor(
    @Inject(NestJwtService) private readonly _nestJwtService: NestJwtService,
    @Inject(ConfigService) private readonly _configService: ConfigService,
  ) {}

  // Regular Sign
  async sign(payload: any): Promise<string> {
    return this._nestJwtService.signAsync(payload, {
      secret: this._configService.get<string>('jwt.secret'),
      expiresIn: '10m',
    });
  }

  async signAccessToken(payload: any): Promise<string> {
    return this._nestJwtService.signAsync(payload, {
      secret: this._configService.get<string>('jwt.accessSecret'),
      expiresIn: this._configService.get<number>('jwt.accessExpiry'),
    });
  }

  async signRefreshToken(payload: any): Promise<string> {
    return this._nestJwtService.signAsync(payload, {
      secret: this._configService.get<string>('jwt.refreshSecret'),
      expiresIn: this._configService.get<number>('jwt.refreshExpiry'),
    });
  }

  // Regular Verify
  verify(data: string): any {
    return this._nestJwtService.verify(data, {
      secret: this._configService.get<string>('jwt.secret'),
    });
  }

  verifyToken(token: string, isRefreshToken = false): any {
    return this._nestJwtService.verify(token, {
      secret: isRefreshToken
        ? this._configService.get<string>('jwt.refreshSecret')
        : this._configService.get<string>('jwt.accessSecret'),
    });
  }
}
