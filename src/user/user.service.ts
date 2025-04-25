import { Injectable } from '@nestjs/common';
import { PrismaService } from './../prisma/prisma.service';
import { Inject } from '@nestjs/common';
import { UserInfoResponseDto } from './dto/user-info.dto';

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
    await this.createAuditLog(user.id, 'USER_INFO_ACCESSED', 'INFO', {});
    return response;
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
}
