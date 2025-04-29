import {
  BadRequestException,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from './../prisma/prisma.service';
import { Inject } from '@nestjs/common';
import { UserInfoResponseDto } from './dto/user-info.dto';
import { UpdateUserInfoDto } from './dto/update-user-info.dto';
import { UpdateEmailDto } from './dto/update-email.dto';
import { compare, hash } from 'bcrypt';
import { randomBytes, createHash } from 'crypto';
import { ConfigService } from '@nestjs/config';
import { UpdatePhoneDto } from './dto/update-phone.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';
import zxcvbn from 'zxcvbn';
import { firstValueFrom } from 'rxjs';
import { HttpService } from '@nestjs/axios';
import { JwtService } from './../auth/jwt.service';

@Injectable()
export class UserService {
  private readonly _logger: Logger;

  constructor(
    @Inject(PrismaService) private readonly _prismaService: PrismaService,
    @Inject(ConfigService) private readonly _configService: ConfigService,
    @Inject(HttpService) private readonly _httpService: HttpService,
    @Inject(JwtService) private readonly _jwtService: JwtService,
  ) {
    this._logger = new Logger(UserService.name);
  }

  async getUserInfo(data: Record<string, any>): Promise<UserInfoResponseDto> {
    const { sub: userId } = data;

    const user = await this._prismaService.user.findUnique({
      where: { id: userId },
    });

    // Get active sessions
    const sessions = await this._prismaService.session.findMany({
      where: { userId, isActive: true },
      orderBy: { createdAt: 'desc' },
    });

    // Get user's agencies
    const userAgencies = await this._prismaService.userAgency.findMany({
      where: { userId, isActive: true },
      include: { agency: true },
    });

    // Format response
    const response: UserInfoResponseDto = {
      user: {
        id: user.id,
        email: user.emailAddress,
        firstName: user.firstName,
        lastName: user.lastName,
        emailVerified: !!user.emailVerifiedAt,
        mfaEnabled: user.mfaEnabled,
        createdAt: user.createdAt,
        lastLogin: user.lastLoginAt || undefined,
        // phone: user.phone || undefined, // TODO: Include in User Model (Prisma)
        // phoneVerified: !!user.phoneVerifiedAt,
        // metadata: user.metadata || {},
      },
      security: {
        mfaEnabled: user.mfaEnabled,
        mfaMethods: await this.getUserMfaMethods(user.id),
        activeSessions: sessions.map((session) => ({
          id: session.id,
          metadata: session.metadata,
          createdAt: session.createdAt,
          lastActivityAt: session.lastActivityAt,
        })),
      },
    };

    // Add agencies if present
    if (userAgencies.length > 0) {
      response.agencies = userAgencies.map((ua) => ({
        id: ua.agency.id,
        name: ua.agency.name,
        domain: ua.agency.domain,
        role: ua.role,
      }));
    }

    // TODO: Include in User Model (Prisma)
    // Add app metadata if present
    // if (user.appMetadata) {
    //   response.appMetadata = user.appMetadata;
    // }

    // Create audit log
    await this._prismaService.auditLog.create({
      data: {
        userId,
        eventType: 'USER_INFO_ACCESSED',
        severity: 'INFO',
        details: {},
      },
    });
    return response;
  }

  async updateUserInfo(
    user: Record<string, any>,
    data: UpdateUserInfoDto,
  ): Promise<{ message: string }> {
    const { sub: userId } = user;

    if (Object.keys(data).length === 0) {
      throw new BadRequestException({
        message: 'No valid fields to update',
      });
    }
    try {
      return await this._prismaService.$transaction(async (prisma) => {
        // Update user
        await prisma.user.update({
          where: { id: userId },
          data,
        });

        // Create audit log
        await prisma.auditLog.create({
          data: {
            userId,
            eventType: 'USER_INFO_UPDATED',
            severity: 'INFO',
            details: {
              updatedFields: Object.keys(data).filter(
                (key) => data[key] !== undefined,
              ),
            },
          },
        });

        return { message: 'User information updated successfully' };
      });
    } catch {
      throw new BadRequestException({
        message: 'Failed to update user information',
      });
    }
  }

  initiatePhoneUpdate(user: Record<string, any>, data: UpdatePhoneDto) {
    const { sub: userId } = user;
    return this._prismaService.$transaction(async (prisma) => {
      // Get current user with password hash
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          emailAddress: true,
          passwordHash: true,
        },
      });

      // Verify password
      const passwordValid = await compare(data.password, user.passwordHash);
      if (!passwordValid) {
        await prisma.auditLog.create({
          data: {
            userId,
            eventType: 'PHONE_UPDATE_FAILED',
            severity: 'WARNING',
            details: { reason: 'invalid_password' },
          },
        });
        throw new UnauthorizedException({
          message: 'Current password is incorrect',
        });
      }

      // Check if phone is already in use
      const phoneExists = await prisma.user.findFirst({
        where: {
          phone: data.newPhone,
          id: { not: userId },
        },
        select: { id: true },
      });

      if (phoneExists) {
        throw new BadRequestException({
          message: 'Phone number is already in use',
        });
      }

      // Generate verification code
      const verificationCode = Math.floor(
        100000 + Math.random() * 900000,
      ).toString();

      // Update user record
      await prisma.user.update({
        where: { id: userId },
        data: {
          pendingPhone: data.newPhone,
          phoneVerificationCode: verificationCode,
          phoneVerificationSentAt: new Date(),
        },
      });

      // TODO: Send verification SMS

      // Create audit log
      await prisma.auditLog.create({
        data: {
          userId,
          eventType: 'PHONE_UPDATE_INITIATED',
          severity: 'INFO',
          details: { new_phone: data.newPhone },
        },
      });

      return { message: 'Verification code sent to your new phone number' };
    });
  }

  initiateEmailUpdate(user: Record<string, any>, data: UpdateEmailDto) {
    const { sub: userId } = user;
    return this._prismaService.$transaction(async (prisma) => {
      // Get current user with password hash
      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: {
          id: true,
          emailAddress: true,
          passwordHash: true,
        },
      });

      // Verify password
      const passwordValid = await compare(data.password, user.passwordHash);
      if (!passwordValid) {
        await prisma.auditLog.create({
          data: {
            user: { connect: { id: userId } },
            eventType: 'EMAIL_UPDATE_FAILED',
            severity: 'WARNING',
            details: { reason: 'invalid_password' },
          },
        });
        throw new UnauthorizedException({
          message: 'Current password is incorrect',
        });
      }

      // Check if email is already in use
      const emailExists = await prisma.user.findUnique({
        where: { emailAddress: data.newEmail },
        select: { id: true },
      });

      if (emailExists) {
        throw new BadRequestException({
          message: 'Email address is already in use',
        });
      }

      // Generate verification token
      const verificationToken = randomBytes(32).toString('hex');

      // Update user record
      await prisma.user.update({
        where: { id: userId },
        data: {
          pendingEmail: data.newEmail,
          emailVerificationToken: verificationToken,
          emailVerificationSentAt: new Date(),
        },
      });

      // TODO: Send verification email

      // Create audit log
      await prisma.auditLog.create({
        data: {
          user: { connect: { id: userId } },
          eventType: 'EMAIL_UPDATE_INITIATED',
          severity: 'INFO',
          details: { newEmail: data.newEmail },
        },
      });

      return {
        message: 'Please check your new email for verification instructions',
      };
    });
  }

  verifyEmailUpdate(token: string) {
    return this._prismaService.$transaction(async (prisma) => {
      // Get token expiration hours from config
      const expiryHours = this._configService.get<number>(
        'security.email.verification.expiryHours',
      );

      // Find user with valid token
      const user = await prisma.user.findFirst({
        where: {
          emailVerificationToken: token,
          emailVerificationSentAt: {
            gte: new Date(Date.now() - expiryHours * 60 * 60 * 1000),
          },
        },
        select: {
          id: true,
          emailAddress: true,
          pendingEmail: true,
        },
      });

      if (!user || !user.pendingEmail) {
        throw new BadRequestException({
          message: 'Invalid or expired verification token',
        });
      }

      // Check if new email is already taken
      const emailExists = await prisma.user.findUnique({
        where: { emailAddress: user.pendingEmail },
        select: { id: true },
      });

      if (emailExists) {
        throw new BadRequestException({
          message: 'Email address is already in use',
        });
      }

      // Store old email before update
      const oldEmail = user.emailAddress;

      // Update user record
      const updatedUser = await prisma.user.update({
        where: { id: user.id },
        data: {
          emailAddress: user.pendingEmail,
          pendingEmail: null,
          emailVerificationToken: null,
          emailVerificationSentAt: null,
          emailVerifiedAt: new Date(),
        },
      });

      // Revoke all sessions
      await prisma.session.deleteMany({
        where: { userId: user.id },
      });

      // Create audit log
      await prisma.auditLog.create({
        data: {
          userId: user.id,
          eventType: 'EMAIL_UPDATED',
          severity: 'INFO',
          details: {
            oldEmail: oldEmail,
            newEmail: updatedUser.emailAddress,
          },
        },
      });

      return {
        message:
          'Email updated successfully. Please log in with your new email.',
      };
    });
  }

  verifyPhoneUpdate(user: Record<string, any>, code: string) {
    const { sub: userId } = user;
    return this._prismaService.$transaction(async (prisma) => {
      // Get code expiration time from config

      // Get token expiration hours from config
      const expiryMinutes = this._configService.get<number>(
        'security.phone.verification.expiryMinutes',
      );

      // Find user with valid verification code
      const user = await prisma.user.findUnique({
        where: {
          id: userId,
          phoneVerificationSentAt: {
            gte: new Date(Date.now() - expiryMinutes * 60 * 1000),
          },
        },
        select: {
          id: true,
          pendingPhone: true,
          phoneVerificationCode: true,
        },
      });

      if (!user || user.phoneVerificationCode !== code) {
        throw new BadRequestException({
          message: 'Invalid or expired verification code',
        });
      }

      // Update user record
      const updatedUser = await prisma.user.update({
        where: { id: userId },
        data: {
          phone: user.pendingPhone,
          pendingPhone: null,
          phoneVerificationCode: null,
          phoneVerificationSentAt: null,
          phoneVerifiedAt: new Date(),
        },
      });

      // Create audit log
      await prisma.auditLog.create({
        data: {
          userId,
          eventType: 'PHONE_UPDATED',
          severity: 'INFO',
          details: {
            newPhone: updatedUser.phone,
          },
        },
      });

      return { message: 'Phone number verified successfully' };
    });
  }

  async passwordUpdate(
    dto: UpdatePasswordDto,
    user: Record<string, any>,
    metadata: Record<string, any>,
  ) {
    const { sub: userId } = user;
    const { ipAddress, userAgent } = metadata;
    const { currentPassword, newPassword } = dto;

    // Rate limiting check
    await this.checkRateLimiting(ipAddress, userId);

    // Current User
    const dbUser = await this._prismaService.user.findUnique({
      where: { id: userId },
      select: { passwordHash: true },
    });

    // Verify current password
    if (!dbUser || !(await compare(currentPassword, dbUser.passwordHash))) {
      // Create audit log
      await this._prismaService.auditLog.create({
        data: {
          userId,
          eventType: 'PASSWORD_CHANGE_FAILED',
          severity: 'WARNING',
          details: { reason: 'invalid_current_password', ipAddress },
        },
      });
      throw new UnauthorizedException({
        message: 'Current password is incorrect',
      });
    }

    // Check if new password is the same as current
    if (await compare(newPassword, dbUser.passwordHash)) {
      throw new BadRequestException({
        message: 'New password must be different from current password',
      });
    }

    // Validate password strength
    const passwordStrength = zxcvbn(newPassword);
    if (passwordStrength.score < 3) {
      throw new BadRequestException({
        message: 'Password is too weak',
        feedback: passwordStrength.feedback,
      });
    }

    // Check password history if enabled
    const historyLimit =
      this._configService.get<number>('security.password.history') ?? 0;
    if (historyLimit > 0) {
      const recentPasswords =
        await this._prismaService.passwordHistory.findMany({
          where: { userId },
          orderBy: { createdAt: 'desc' },
          take: historyLimit,
          select: { passwordHash: true },
        });

      for (const entry of recentPasswords) {
        const isSame = await compare(newPassword, entry.passwordHash); // newPassword = user's new password
        if (isSame) {
          throw new BadRequestException({
            message:
              'Password has been used recently. Please choose a different password.',
          });
        }
      }
    }

    if (
      this._configService.get<boolean>(`security.password.checkCompromised`)
    ) {
      const isCompromised = await this.checkCompromisedPassword(newPassword);
      if (isCompromised) {
        throw new BadRequestException({
          message:
            'This password has been found in data breaches. Please choose a different password.',
        });
      }
    }

    return this._prismaService.$transaction(async (prisma) => {
      try {
        // Generate password hash
        const passwordHash = await hash(
          newPassword,
          this._configService.get<number>('security.password.bcryptRounds'),
        );

        // Store old password in history if enabled
        if (this._configService.get<number>(`security.password.history`) > 0) {
          await prisma.passwordHistory.create({
            data: { userId, passwordHash: dbUser.passwordHash },
          });

          // Clean up old history entries
          // 1. Find the 'cutoff' createdAt timestamp
          const cutoffEntry = await prisma.passwordHistory.findFirst({
            where: { userId },
            orderBy: { createdAt: 'desc' },
            skip: this._configService.get<number>(`security.password.history`), // Number of passwords to keep
            take: 1,
            select: { createdAt: true },
          });

          if (!cutoffEntry) {
            // If there's no such password, nothing to delete
            return;
          }

          // 2. Delete all password histories older than the cutoff
          await prisma.passwordHistory.deleteMany({
            where: { userId, createdAt: { lt: cutoffEntry.createdAt } },
          });
        }

        // Update password
        await prisma.user.update({
          where: { id: userId },
          data: {
            passwordHash,
            passwordChangedAt: new Date(),
            forcePasswordChange: false,
          },
        });

        await prisma.auditLog.create({
          data: {
            userId,
            eventType: 'PASSWORD_CHANGED',
            severity: 'INFO',
            details: { ipAddress },
          },
        });

        // Create a session
        const session = await prisma.session.create({
          data: {
            user: { connect: { id: userId } },
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
            user: { connect: { id: userId } },
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

        // TODO: Send a Notification Email

        return {
          message: 'Password updated successfully',
          accessToken,
          refreshToken,
          expiresIn: this._configService.get<number>('jwt.accessExpiry'),
        };
      } catch (error) {
        await this._prismaService.auditLog.create({
          data: {
            userId: null,
            eventType: 'REGISTRATION_FAILED',
            severity: 'ERROR',
            details: { error: error.message, ipAddress },
          },
        });
        throw error;
      }
    });
  }

  async getUserAgencies(user: Record<string, any>) {
    const { sub: userId } = user;

    const userAgencies = await this._prismaService.userAgency.findMany({
      where: {
        userId,
        isActive: true,
        agency: { isActive: true },
      },
      select: {
        role: true,
        agency: {
          select: {
            id: true,
            uuid: true,
            name: true,
            domain: true,
            config: { take: 1, select: { config: true } },
          },
        },
      },
    });

    const agencies = userAgencies.map(({ role, agency }) => {
      // const config =
      //   agency.config && agency.config.length > 0
      //     ? agency.config[0].config
      //     : DEFAULT_AGENCY_CONFIG;

      return {
        id: agency.id,
        uuid: agency.uuid,
        name: agency.name,
        domain: agency.domain,
        role,
        // config,
      };
    });

    await this._prismaService.auditLog.create({
      data: {
        userId,
        eventType: 'AGENCIES_LISTED',
        severity: 'INFO',
        details: {},
      },
    });

    return { agencies };
  }

  /*
   * Private Methods
   */
  private getUserMfaMethods(userId: number): Promise<any[]> {
    return this._prismaService.mfaMethod.findMany({
      where: { userId },
      select: {
        id: true,
        type: true,
        createdAt: true,
        lastUsedAt: true,
      },
    });
  }

  async checkCompromisedPassword(password: string): Promise<boolean> {
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
      this._logger.error('Compromised password check failed:', error);
      return false;
    }
  }

  private async checkRateLimiting(ipAddress: string, userId: number) {
    const attempts = this._configService.get<number>(
      `security.rateLimit.passwordReset.attempts`,
    );
    const timeframe = this._configService.get<number>(
      `security.rateLimit.passwordReset.timeframe`,
    );

    const count = await this._prismaService.failedLoginAttempt.count({
      where: {
        metadata: { path: '$.ipAddress', equals: ipAddress },
        createdAt: { gte: new Date(Date.now() - timeframe * 1000) },
      },
    });

    if (count >= attempts) {
      await this._prismaService.auditLog.create({
        data: {
          userId,
          eventType: 'PASSWORD_RESET_RATE_LIMIT_EXCEEDED',
          severity: 'WARNING',
          details: { ipAddress },
        },
      });
      throw new UnauthorizedException({
        message: 'Too many password change attempts. Please try again later.',
      });
    }
  }
}
