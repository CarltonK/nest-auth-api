import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from './../prisma/prisma.service';
import { Inject } from '@nestjs/common';
import { UserInfoResponseDto } from './dto/user-info.dto';
import { UpdateUserInfoDto } from './dto/update-user-info.dto';
import { UpdateEmailDto } from './dto/update-email.dto';
import { compare } from 'bcrypt';
import { randomBytes } from 'crypto';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class UserService {
  constructor(
    @Inject(PrismaService) private readonly _prismaService: PrismaService,
    @Inject(ConfigService) private readonly _configService: ConfigService,
  ) {}

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
}
