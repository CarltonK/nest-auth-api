import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from './../prisma/prisma.service';
import { Inject } from '@nestjs/common';
import { UserInfoResponseDto } from './dto/user-info.dto';
import { UpdateUserInfoDto } from './dto/update-user-info.dto';

@Injectable()
export class UserService {
  constructor(
    @Inject(PrismaService) private readonly _prismaService: PrismaService,
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
    } catch (error) {
      throw new BadRequestException({
        message: 'Failed to update user information',
      });
    }
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
