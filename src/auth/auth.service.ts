import {
  BadRequestException,
  ConflictException,
  Inject,
  Injectable,
  Logger,
} from '@nestjs/common';
import { RegisterUserDto } from './dto/register.dto';
import { ConfigService } from '@nestjs/config';
import { createHash, randomBytes } from 'crypto';
import zxcvbn from 'zxcvbn';
import { hash } from 'bcrypt';
import { firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { PrismaService } from './../prisma/prisma.service';

@Injectable()
export class AuthService {
  private readonly _logger: Logger;

  constructor(
    @Inject(ConfigService) private readonly _configService: ConfigService,
    @Inject(PrismaService) private readonly _prismaService: PrismaService,
    @Inject(HttpService) private readonly _httpService: HttpService,
  ) {
    this._logger = new Logger(AuthService.name);
  }

  async registerUser(registerDto: RegisterUserDto, ipAddress: string) {
    const { password, email, firstName, lastName } = registerDto;

    // Validate password strength
    const passwordStrength = zxcvbn(registerDto.password);
    if (passwordStrength.score < 3) {
      throw new BadRequestException({
        message: 'Password is too weak',
        feedback: passwordStrength.feedback,
      });
    }

    // Check compromised password
    if (
      this._configService.get<boolean>('security.password.checkCompromised')
    ) {
      const isCompromised = await this.checkCompromisedPassword(password);
      if (isCompromised) {
        throw new BadRequestException({
          message:
            'This password has been found in data breaches. Please choose a different password.',
        });
      }
    }

    return this._prismaService.$transaction(async (prisma) => {
      try {
        // Check existing user
        const existingUser = await prisma.user.findUnique({
          where: { emailAddress: email },
        });

        if (existingUser) {
          throw new ConflictException({
            message: 'Email already registered',
          });
        }

        // Generate password hash
        const passwordHash = await hash(
          password,
          this._configService.get<number>('security.password.bcryptRounds'),
        );

        // Generate verification token
        const verificationToken = this.generateVerificationToken();

        // Create user
        const user = await prisma.user.create({
          data: {
            emailAddress: email,
            firstName,
            lastName,
            passwordHash,
            emailVerificationToken: verificationToken,
            metadata: this.createUserMetadata(ipAddress),
            passwordChangedAt: new Date(),
            emailVerificationSentAt: new Date(),
          },
        });

        // Store password history if enabled
        if (this._configService.get<number>('security.password.history')) {
          await this._prismaService.passwordHistory.create({
            data: { userId: user.id, passwordHash },
          });
        }

        // Create audit log
        await this._prismaService.auditLog.create({
          data: {
            userId: user.id,
            eventType: 'USER_REGISTERED',
            severity: 'INFO',
            details: { ipAddress, email },
          },
        });

        // Send verification email
        // await this.mailService.sendVerificationEmail(
        //   user.email,
        //   verificationToken,
        // );

        // Prepare response
        const response = {
          message:
            'Registration successful. Please check your email for verification.',
          requiresVerification: true,
        };

        // Auto-login if enabled (implement session logic separately)
        if (
          this._configService.get<boolean>('security.registration.autoLogin')
        ) {
          // Implement session creation and token generation
        }

        return response;
      } catch (error) {
        await this._prismaService.auditLog.create({
          data: {
            eventType: 'REGISTRATION_FAILED',
            severity: 'ERROR',
            details: { error: error.message, email, ipAddress },
          },
        });
        throw error;
      }
    });
  }

  private async checkCompromisedPassword(password: string): Promise<boolean> {
    try {
      const hash = createHash('sha1')
        .update(password)
        .digest('hex')
        .toUpperCase();
      const prefix = hash.substring(0, 5);
      const suffix = hash.substring(5);

      const url = `https://api.pwnedpasswords.com/range/${prefix}`;
      const response = await firstValueFrom(this._httpService.get(url));

      return response.data.split('\n').some((line: string) => {
        const [hashSuffix] = line.split(':');
        return hashSuffix === suffix;
      });
    } catch (error) {
      // Log error but don't block registration
      this._logger.error('Compromised password check failed:', error);
      return false;
    }
  }

  private generateVerificationToken(): string {
    const env = this._configService.get<string>('NODE_ENV');
    return ['development', 'test'].includes(env)
      ? 'TEST_VERIFICATION_TOKEN'
      : randomBytes(32).toString('hex');
  }

  private createUserMetadata(ipAddress: string): any {
    const timestamp = new Date().toISOString();
    return { registration: { ipAddress, timestamp } };
  }
}
