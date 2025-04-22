import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  UnauthorizedException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { RegisterUserDto } from './dto/register.dto';
import { ConfigService } from '@nestjs/config';
import { createHash, randomBytes } from 'crypto';
import zxcvbn from 'zxcvbn';
import { hash, compare } from 'bcrypt';
import { firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { PrismaService } from './../prisma/prisma.service';
import { UAParser } from 'ua-parser-js';
import { lookup } from 'geoip-lite';
import { LoginUserDto } from './dto/login.dto';
import { JwtService } from './jwt.service';
import { VerifyEmailDto } from './dto/verifyEmail.dto';

@Injectable()
export class AuthService {
  private readonly _logger: Logger;
  private readonly _testToken = 'TEST_VERIFICATION_TOKEN';

  constructor(
    @Inject(ConfigService) private readonly _configService: ConfigService,
    @Inject(PrismaService) private readonly _prismaService: PrismaService,
    @Inject(HttpService) private readonly _httpService: HttpService,
    @Inject(JwtService) private readonly _jwtService: JwtService,
  ) {
    this._logger = new Logger(AuthService.name);
  }

  async registerUser(
    registerDto: RegisterUserDto,
    metadata: Record<string, any>,
  ) {
    const { password, emailAddress, firstName, lastName } = registerDto;
    const { ipAddress } = metadata;

    // Rate limiting check
    await this.checkRateLimiting(ipAddress, 'register');

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
          where: { emailAddress },
        });

        if (existingUser) {
          throw new UnprocessableEntityException({
            message: 'Invalid registration details',
          });
        }

        // Generate password hash
        const passwordHash = await hash(
          password,
          this._configService.get<number>('security.password.bcryptRounds'),
        );

        // Generate verification token
        const verificationToken = this.generateVerificationToken();

        // Request Metadata
        const requestMetadata = this.createUserMetadata(metadata);

        // Create user
        const user = await prisma.user.create({
          data: {
            emailAddress,
            firstName,
            lastName,
            passwordHash,
            emailVerificationToken: verificationToken,
            metadata: { registration: requestMetadata },
            passwordChangedAt: new Date(),
            emailVerificationSentAt: new Date(),
          },
          select: { id: true },
        });

        // Store password history if enabled
        if (this._configService.get<number>('security.password.history')) {
          await prisma.passwordHistory.create({
            data: { user: { connect: { id: user.id } }, passwordHash },
          });
        }

        // Create audit log
        await prisma.auditLog.create({
          data: {
            user: { connect: { id: user.id } },
            eventType: 'USER_REGISTERED',
            severity: 'INFO',
            details: { ipAddress },
          },
        });

        // TODO: Send verification email
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
        await this.createAuditLog(null, 'REGISTRATION_FAILED', 'ERROR', {
          error: error.message,
          emailAddress,
          ipAddress,
        });
        throw error;
      }
    });
  }

  async loginUser(loginDto: LoginUserDto, metadata: Record<string, any>) {
    const { emailAddress, password } = loginDto;

    // Request Metadata
    const requestMetadata = this.createUserMetadata(metadata);

    const { ipAddress } = requestMetadata;

    // Rate limiting check
    await this.checkRateLimiting(ipAddress, 'login');

    return this._prismaService.$transaction(async (prisma) => {
      try {
        const user = await prisma.user.findUnique({
          where: { emailAddress, isActive: true, isLocked: false },
          include: { mfaMethods: true },
        });

        if (!user || !(await compare(password, user.passwordHash))) {
          await this.handleFailedLogin(emailAddress, ipAddress);
          throw new UnauthorizedException({ message: 'Invalid credentials' });
        }

        if (!user.emailVerifiedAt) {
          throw new ForbiddenException({ message: 'Email not verified' });
        }

        // TODO
        // if (user.mfaEnabled) {
        //   return this.handleMfaFlow(user);
        // }

        // Create a session
        const session = await prisma.session.create({
          data: {
            user: { connect: { id: user.id } },
            metadata,
            expiresAt: new Date(
              Date.now() + this._configService.get<number>('session.expiry'),
            ),
          },
        });

        // Generate tokens
        const accessPayload = {
          sub: user.id,
          session: session.id,
          type: 'access',
        };
        const refreshPayload = {
          sub: user.id,
          session: session.id,
          type: 'refresh',
        };

        const [accessToken, refreshToken] = await Promise.all([
          this._jwtService.signAccessToken(accessPayload),
          this._jwtService.signRefreshToken(refreshPayload),
        ]);

        // Encrypt and store refresh token
        const hashedToken = await hash(
          refreshToken,
          this._configService.get<number>('security.password.bcryptRounds'),
        );

        await prisma.authToken.create({
          data: {
            user: { connect: { id: user.id } },
            session: { connect: { id: session.id } },
            token: hashedToken,
            type: 'refresh',
            userAgent: JSON.stringify(metadata),
            expiresAt: new Date(
              Date.now() +
                this._configService.get<number>('jwt.refreshExpiry') * 1000,
            ),
          },
        });

        // Set last login
        await prisma.user.update({
          where: { id: user.id },
          data: { lastLoginAt: new Date() },
        });

        await prisma.auditLog.create({
          data: {
            user: { connect: { id: user.id } },
            eventType: 'USER_LOGGED_IN',
            severity: 'INFO',
            details: requestMetadata,
          },
        });

        return {
          accessToken,
          refreshToken,
          expiresIn: this._configService.get<number>('jwt.accessExpiry'),
          sessionId: session.id,
        };
      } catch (error) {
        await this.createAuditLog(null, 'LOGIN_FAILED', 'ERROR', {
          error: error.message,
          emailAddress,
          ipAddress,
        });
        throw error;
      }
    });
  }

  async verifyEmail(
    verifyEmailDto: VerifyEmailDto,
    metadata: Record<string, any>,
  ) {
    const { emailAddress, token } = verifyEmailDto;

    const user = await this._prismaService.user.findFirst({
      ...this.buildVerificationQuery(emailAddress, token),
      select: { id: true, emailAddress: true },
    });

    if (!user) {
      throw new BadRequestException({
        message: 'Invalid or expired verification token',
      });
    }

    return this._prismaService.$transaction(async (prisma) => {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          emailVerifiedAt: new Date(),
          emailVerificationToken: null,
          emailVerificationSentAt: null,
        },
      });

      await prisma.auditLog.create({
        data: {
          user: { connect: { id: user.id } },
          eventType: 'EMAIL_VERIFIED',
          severity: 'INFO',
          details: {
            ...metadata,
            environment: this._configService.get('NODE_ENV'),
          },
        },
      });

      const response = { message: 'Email verified successfully' };
      return response;
    });
  }

  async logoutUser(
    payload: Record<string, any>,
    metadata: Record<string, any>,
  ) {
    const { sub: userId, session: sessionId } = payload;
    try {
      return this._prismaService.$transaction(async (prisma) => {
        // Revoke current session
        await prisma.session.update({
          where: { id: sessionId, userId },
          data: { isActive: false },
        });

        // Revoke all refresh tokens
        await prisma.authToken.updateMany({
          where: { userId, type: 'refresh', revoked: false },
          data: { revoked: true },
        });

        // Audit Log
        await prisma.auditLog.create({
          data: {
            user: { connect: { id: userId } },
            eventType: 'USER_LOGGED_OUT',
            severity: 'INFO',
            details: { ...metadata, sessionId },
          },
        });

        return { message: 'Logged out successfully' };
      });
    } catch (error) {
      await this.createAuditLog(null, 'LOGOUT_FAILED', 'ERROR', {
        error: error.message,
      });
      throw error;
    }
  }

  /*
   * Private Methods
   */
  private async checkRateLimiting(ipAddress: string, type: string) {
    const attempts = this._configService.get<number>(
      `security.rateLimit.${type}.attempts`,
    );
    const timeframe = this._configService.get<number>(
      `security.rateLimit.${type}.timeframe`,
    );

    const count = await this._prismaService.failedLoginAttempt.count({
      where: {
        metadata: { path: '$.ipAddress', equals: ipAddress },
        createdAt: { gte: new Date(Date.now() - timeframe * 1000) },
      },
    });

    if (count >= attempts) {
      await this.createAuditLog(null, 'LOGIN_RATE_LIMIT_EXCEEDED', 'WARNING', {
        ipAddress,
      });
      throw new UnauthorizedException({ message: 'Too many login attempts' });
    }
  }

  private async handleFailedLogin(emailAddress: string, ipAddress: string) {
    const metadata = { ipAddress };
    await this._prismaService.failedLoginAttempt.create({
      data: { emailAddress, metadata },
    });

    const attempts = await this._prismaService.failedLoginAttempt.count({
      where: {
        emailAddress,
        createdAt: { gte: new Date(Date.now() - 3600000) },
      },
    });

    if (
      attempts >=
      this._configService.get<number>('security.suspiciousThreshold')
    ) {
      // TODO: await this.sendSuspiciousActivityAlert(email, ipAddress);
    }

    if (
      attempts >= this._configService.get<number>('security.maxFailedAttempts')
    ) {
      await this._prismaService.user.update({
        where: { emailAddress },
        data: { isLocked: true },
      });
      throw new UnprocessableEntityException({
        message: 'Account temporarily locked',
      });
    }

    await this.createAuditLog(null, 'LOGIN_FAILED', 'WARNING', {
      emailAddress,
      ipAddress,
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
      ? this._testToken
      : randomBytes(32).toString('hex');
  }

  private createUserMetadata(metadata: Record<string, any>): any {
    const { ipAddress, userAgent } = metadata;

    // Parse User-Agent
    const parser = new UAParser(userAgent);
    const browser = parser.getBrowser();
    const os = parser.getOS();
    const device = parser.getDevice();

    // Get location from IP
    const geo = lookup(ipAddress);
    const location = geo ? `${geo.city}, ${geo.country}` : 'Unknown';

    const timestamp = new Date().toISOString();

    return {
      ipAddress,
      timestamp,
      device: device.type,
      browser: browser.name,
      platform: os.name,
      location,
    };
  }

  private createAuditLog(
    userId: number | null,
    eventType: string,
    severity: string,
    details: Record<string, any>,
  ) {
    return this._prismaService.auditLog.create({
      data: {
        userId,
        eventType,
        severity,
        details,
      },
    });
  }

  private buildVerificationQuery(emailAddress: string, token: string) {
    const isTestEnv = ['development', 'test'].includes(
      this._configService.get('NODE_ENV'),
    );

    const baseWhere = {
      emailAddress,
      emailVerificationToken: token,
      emailVerifiedAt: null,
    };

    if (isTestEnv && token === this._testToken) {
      return { where: baseWhere };
    }

    return {
      where: {
        ...baseWhere,
        emailVerificationSentAt: {
          gte: this.getVerificationExpiryDate(),
        },
      },
    };
  }

  private getVerificationExpiryDate(): Date {
    const expiryHours = this._configService.get<number>(
      'security.email.verification.expiryHours',
    );
    return new Date(Date.now() - expiryHours * 60 * 60 * 1000);
  }
}
