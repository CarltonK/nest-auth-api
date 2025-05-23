import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  InternalServerErrorException,
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
import { RefreshTokenDto } from './dto/refresh.dto';
import { PasswordResetDto } from './dto/password-reset.dto';
import { OAuthCallbackDto } from './dto/oauth-callback.dto';
import { OAuthService } from './oauth.service';

// TODO: Use a Password Service
@Injectable()
export class AuthService {
  private readonly _logger: Logger;
  private readonly _testToken = 'TEST_VERIFICATION_TOKEN';

  constructor(
    @Inject(ConfigService) private readonly _configService: ConfigService,
    @Inject(PrismaService) private readonly _prismaService: PrismaService,
    @Inject(HttpService) private readonly _httpService: HttpService,
    @Inject(JwtService) private readonly _jwtService: JwtService,
    @Inject(OAuthService) private readonly _oauthService: OAuthService,
    @Inject('OAUTH_PROVIDERS')
    private readonly _oauthProviders: Record<string, any>,
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
    const { userAgent } = metadata;

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

        // TODO: Handle MFA
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
        const hashedToken = createHash('sha256')
          .update(refreshToken)
          .digest('hex');

        await prisma.authToken.create({
          data: {
            user: { connect: { id: user.id } },
            session: { connect: { id: session.id } },
            token: hashedToken,
            type: 'refresh',
            userAgent,
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

  async refreshToken(dto: RefreshTokenDto, metadata: Record<string, any>) {
    // Validate the refresh token
    let payload: Record<string, any>;
    const { refreshToken } = dto;
    const { userAgent } = metadata;
    try {
      payload = this._jwtService.verifyToken(refreshToken, true);
    } catch {
      throw new UnauthorizedException({ message: 'Invalid refresh token' });
    }

    if (!payload || payload.type !== 'refresh') {
      throw new UnauthorizedException({ message: 'Invalid refresh token' });
    }

    const { sub } = payload;

    // Hash the token for DB lookup
    const hashedToken = createHash('sha256').update(refreshToken).digest('hex');

    // Verify token in database
    const validToken = await this._prismaService.authToken.findFirst({
      where: {
        token: hashedToken,
        type: 'refresh',
        revoked: false,
        expiresAt: { gt: new Date() },
      },
    });

    if (!validToken) {
      throw new UnauthorizedException({
        message: 'Invalid or expired refresh token',
      });
    }

    return this._prismaService.$transaction(async (prisma) => {
      // Revoke old refresh token
      await prisma.authToken.update({
        where: { id: validToken.id },
        data: { revoked: true },
      });

      // Create new session
      const session = await prisma.session.create({
        data: {
          user: { connect: { id: sub } },
          expiresAt: new Date(
            Date.now() + parseInt(process.env.SESSION_EXPIRY),
          ),
          metadata,
        },
      });

      // Generate new tokens
      const accessPayload = {
        sub,
        session: session.id,
        type: 'access',
      };
      const refreshPayload = {
        sub,
        session: session.id,
        type: 'refresh',
      };

      const [accessToken, refreshToken] = await Promise.all([
        this._jwtService.signAccessToken(accessPayload),
        this._jwtService.signRefreshToken(refreshPayload),
      ]);

      // Store new refresh token
      const hashedToken = createHash('sha256')
        .update(refreshToken)
        .digest('hex');

      await prisma.authToken.create({
        data: {
          user: { connect: { id: sub } },
          session: { connect: { id: session.id } },
          token: hashedToken,
          type: 'refresh',
          userAgent,
          expiresAt: new Date(
            Date.now() +
              this._configService.get<number>('jwt.refreshExpiry') * 1000,
          ),
        },
      });

      // Create audit log
      const requestMetadata = this.createUserMetadata(metadata);
      await prisma.auditLog.create({
        data: {
          user: { connect: { id: sub } },
          eventType: 'TOKEN_REFRESHED',
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
    });
  }

  async requestPasswordReset(email: string, metadata: Record<string, any>) {
    // Rate limiting check
    const { ipAddress } = metadata;
    await this.checkRateLimiting(ipAddress, 'passwordReset');

    // Check if user exists
    const user = await this._prismaService.user.findFirst({
      where: {
        emailAddress: email,
        isActive: true,
      },
    });

    // Security through obscurity - always return success
    const msg =
      'If your email is registered, you will receive reset instructions shortly';
    if (!user) {
      await this._prismaService.auditLog.create({
        data: {
          eventType: 'PASSWORD_RESET_NONEXISTENT_EMAIL',
          severity: 'INFO',
          details: { email },
        },
      });
      return { message: msg };
    }

    // Generate and store reset token
    const resetToken = randomBytes(32).toString('hex');
    const resetTokenExpiry = new Date(
      Date.now() +
        this._configService.get<number>('security.passwordReset.tokenExpiry'),
    );

    return await this._prismaService.$transaction(async (prisma) => {
      // Update user with reset token
      await prisma.user.update({
        where: { id: user.id },
        data: {
          passwordResetToken: resetToken,
          passwordResetSentAt: resetTokenExpiry,
        },
      });

      // TODO: Send Email

      // Audit log
      const requestMetadata = this.createUserMetadata(metadata);
      await prisma.auditLog.create({
        data: {
          user: { connect: { id: user.id } },
          eventType: 'PASSWORD_RESET_REQUESTED',
          severity: 'INFO',
          details: requestMetadata,
        },
      });

      return { message: msg };
    });
  }

  async resetPassword(dto: PasswordResetDto, metadata: Record<string, any>) {
    // Rate limiting check
    const { ipAddress } = metadata;
    await this.checkRateLimiting(ipAddress, 'passwordResetVerify');

    const requestMetadata = this.createUserMetadata(metadata);

    const { password, resetToken } = dto;

    // Validate password strength
    const passwordStrength = zxcvbn(password);
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

    // Find user with valid reset token
    const user = await this._prismaService.user.findFirst({
      where: {
        passwordResetToken: resetToken,
        passwordResetSentAt: {
          gte: new Date(
            Date.now() -
              this._configService.get<number>(
                'security.passwordReset.tokenExpiry',
              ),
          ),
        },
        isActive: true,
      },
      select: { id: true, passwordHash: true },
    });

    if (!user) {
      await this._prismaService.auditLog.create({
        data: {
          eventType: 'PASSWORD_RESET_INVALID_TOKEN',
          severity: 'WARNING',
          details: requestMetadata,
        },
      });
      throw new BadRequestException({
        message: 'Invalid or expired reset token',
      });
    }

    // Verify new password isn't the same as current
    const isSamePassword = await compare(password, user.passwordHash);
    if (isSamePassword) {
      throw new UnprocessableEntityException({
        message: 'New password must be different from current password',
      });
    }

    return this._prismaService.$transaction(async (prisma) => {
      // Generate password hash
      const passwordHash = await hash(
        password,
        this._configService.get<number>('security.password.bcryptRounds'),
      );
      const now = new Date();

      // Update password
      await prisma.user.update({
        where: { id: user.id },
        data: {
          passwordHash,
          passwordResetToken: null,
          passwordResetSentAt: null,
          passwordChangedAt: now,
          failedAttemptsCount: 0, // Reset failed attempts
          isLocked: false, // Unlock if previously locked
        },
      });

      // Revoke all sessions and tokens
      await prisma.authToken.deleteMany({
        where: { user: { id: user.id } },
      });

      await prisma.session.deleteMany({
        where: { user: { id: user.id } },
      });

      // Audit log
      await prisma.auditLog.create({
        data: {
          user: { connect: { id: user.id } },
          eventType: 'PASSWORD_RESET_SUCCESSFUL',
          severity: 'INFO',
          details: requestMetadata,
        },
      });

      // TODO: Send notification email

      return {
        message:
          'Password has been reset successfully. Please login with your new password.',
      };
    });
  }

  async initiateOauth(provider: string) {
    const config = this._oauthProviders[provider];

    if (!config || !config.enabled) {
      throw new BadRequestException({
        message: 'Invalid or disabled OAuth provider',
      });
    }

    const state = randomBytes(16).toString('hex');

    // Sign via JWT to be verified in callback
    const signedState = await this._jwtService.sign({ state, provider });

    const queryParams = new URLSearchParams({
      client_id: config.client_id,
      redirect_uri: config.redirect_uri,
      response_type: 'code',
      scope: config.scopes.join(' '),
      state: signedState,
    });

    return `${config.auth_endpoint}?${queryParams.toString()}`;
  }

  async handleOAuthCallback(oauthCallbackDto: OAuthCallbackDto) {
    const { state, code, error, errorDescription } = oauthCallbackDto;

    // Handle OAuth error
    if (error) {
      await this.createAuditLog(null, 'OAUTH_ERROR', 'WARNING', {
        error,
        errorDescription,
      });
      throw new BadRequestException({ message: `OAuth error: ${error}` });
    }

    // Verify state and check code
    const statePayload = await this._jwtService.verify(state);
    const { provider } = statePayload;

    if (!statePayload.state) {
      await this.createAuditLog(null, 'OAUTH_STATE_MISMATCH', 'WARNING', {});
      throw new BadRequestException({
        message: 'Invalid state or missing code',
      });
    }

    try {
      // Exchange code for tokens
      const tokenResponse = await this._oauthService.exchangeCodeForTokens(
        provider,
        code,
      );
      if (!tokenResponse?.access_token) {
        throw new BadRequestException({
          message: 'Failed to obtain access token',
        });
      }

      // Fetch user info
      const userInfo = await this._oauthService.fetchUserInfo(
        provider,
        tokenResponse.access_token,
      );
      if (!userInfo?.email) {
        throw new BadRequestException({
          message: 'Failed to obtain user information',
        });
      }

      // Process user authentication
      const result = await this.processOAuthUser(
        provider,
        userInfo,
        tokenResponse,
      );

      const { userId, sessionId } = result;

      // Generate new tokens
      const accessPayload = {
        sub: userId,
        session: sessionId,
        type: 'access',
      };
      const refreshPayload = {
        sub: userId,
        session: sessionId,
        type: 'refresh',
      };

      const [accessToken, refreshToken] = await Promise.all([
        this._jwtService.signAccessToken(accessPayload),
        this._jwtService.signRefreshToken(refreshPayload),
      ]);

      // Store new refresh token
      const hashedToken = createHash('sha256')
        .update(refreshToken)
        .digest('hex');

      await this._prismaService.authToken.create({
        data: {
          user: { connect: { id: userId } },
          session: { connect: { id: sessionId } },
          token: hashedToken,
          type: 'refresh',
          expiresAt: new Date(
            Date.now() +
              this._configService.get<number>('jwt.refreshExpiry') * 1000,
          ),
        },
      });

      await this.createAuditLog(userId, 'OAUTH_LOGIN_SUCCESS', 'INFO', {
        provider,
      });

      return {
        accessToken,
        refreshToken,
        expiresIn: this._configService.get<number>('jwt.accessExpiry'),
        sessionId: sessionId,
      };
    } catch (error) {
      if (error instanceof BadRequestException) {
        throw error;
      }
      await this.createAuditLog(null, 'OAUTH_CALLBACK_ERROR', 'ERROR', {
        error: error.message,
      });
      throw new InternalServerErrorException({
        message: 'OAuth processing failed',
      });
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
      let msg: string;
      let message: string;
      switch (type) {
        case 'login':
          msg = 'LOGIN_RATE_LIMIT_EXCEEDED';
          message = 'login';
          break;
        case 'register':
          msg = 'REGISTRATION_RATE_LIMIT_EXCEEDED';
          message = 'registration';
          break;
        case 'passwordReset':
          msg = 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED';
          message = 'reset';
          break;
        default:
          break;
      }
      await this.createAuditLog(null, msg, 'WARNING', {
        ipAddress,
      });
      throw new UnauthorizedException({
        message: `Too many ${message} attempts. Please try again later`,
      });
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

    await this._prismaService.user.update({
      where: { emailAddress },
      data: { failedAttemptsCount: { increment: 1 } },
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

  private processOAuthUser(
    provider: string,
    userInfo: any,
    tokenResponse: any,
  ) {
    return this._prismaService.$transaction(async (prisma) => {
      // Find or create user
      const user = await prisma.user.upsert({
        where: { emailAddress: userInfo.email },
        create: {
          emailAddress: userInfo.email,
          firstName: userInfo.given_name || userInfo.name?.split(' ')[0],
          lastName: userInfo.family_name || userInfo.name?.split(' ')[1],
          // Generate a random password for OAuth users
          passwordHash: await hash(Math.random().toString(36), 10),
          emailVerifiedAt: new Date(),
          isActive: true,
          metadata: {
            name: userInfo.name || null,
            picture: userInfo.picture || null,
          },
          passwordChangedAt: new Date(),
        },
        update: {
          lastLoginAt: new Date(),
          metadata: {
            name: userInfo.name || null,
            picture: userInfo.picture || null,
          },
        },
      });

      // Find provider in database
      const oauthProvider = await prisma.authOauthprovider.findFirst({
        where: { name: provider },
      });

      if (!oauthProvider) {
        throw new BadRequestException({ message: 'Invalid OAuth provider' });
      }

      // Create or update identity
      await prisma.authUseridentity.upsert({
        where: {
          userId_providerId: {
            userId: user.id,
            providerId: oauthProvider.id,
          },
        },
        create: {
          uuid: crypto.randomUUID(),
          userId: user.id,
          providerId: oauthProvider.id,
          providerUserId: userInfo.sub,
          accessToken: tokenResponse.access_token,
          refreshToken: tokenResponse.refresh_token || null,
          tokenExpiresAt: tokenResponse.expires_in
            ? new Date(Date.now() + tokenResponse.expires_in * 1000)
            : null,
        },
        update: {
          providerUserId: userInfo.sub,
          accessToken: tokenResponse.access_token,
          refreshToken: tokenResponse.refresh_token || null,
          tokenExpiresAt: tokenResponse.expires_in
            ? new Date(Date.now() + tokenResponse.expires_in * 1000)
            : null,
          updatedAt: new Date(),
        },
      });

      // Create session
      const session = await prisma.session.create({
        data: {
          user: { connect: { id: user.id } },
          authToken: {
            create: {
              userId: user.id,
              token: `${crypto.randomUUID()}`,
              type: '',
              expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
            },
          },
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        },
      });

      return {
        userId: user.id,
        sessionId: session.id,
      };
    });
  }
}
