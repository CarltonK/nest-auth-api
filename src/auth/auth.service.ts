import { Injectable } from '@nestjs/common';
import { RegisterUserDto } from './dto/register.dto';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
  constructor(private readonly _configService: ConfigService) {}

  registerUser(registerDto: RegisterUserDto, ipAddress: string) {
    return ipAddress;
  }

  private generateVerificationToken(): string {
    const env = this._configService.get<string>('NODE_ENV');
    return ['development', 'test'].includes(env)
      ? 'TEST_VERIFICATION_TOKEN'
      : crypto.randomBytes(32).toString('hex');
  }

  private createUserMetadata(ipAddress: string): any {
    const timestamp = new Date().toISOString();
    return { registration: { ipAddress, timestamp } };
  }
}
