import { ApiProperty } from '@nestjs/swagger';
import { JsonValue } from 'generated/prisma/runtime/library';

class UserSessionDto {
  @ApiProperty()
  id: string;

  @ApiProperty()
  metadata: JsonValue;

  @ApiProperty()
  createdAt: Date;

  @ApiProperty()
  lastActivityAt: Date;
}

class UserAgencyDto {
  @ApiProperty()
  id: number;

  @ApiProperty()
  name: string;

  @ApiProperty()
  domain: string;

  @ApiProperty()
  role: string;
}

class UserSecurityInfoDto {
  @ApiProperty({
    description: 'Whether MFA is enabled for the account',
    example: true,
  })
  mfaEnabled: boolean;

  @ApiProperty({
    description: 'List of MFA methods configured',
    type: [Object],
    example: [
      { type: 'sms', lastUsed: '2023-01-01T00:00:00Z' },
      { type: 'authenticator', lastUsed: '2023-01-05T00:00:00Z' },
    ],
  })
  mfaMethods: any[];

  @ApiProperty({
    description: 'Active sessions for the user',
    type: [UserSessionDto],
  })
  activeSessions: UserSessionDto[];
}

export class UserInfoResponseDto {
  @ApiProperty({
    description: 'Core user profile information',
  })
  user: {
    id: number;
    email: string;
    firstName: string;
    lastName: string;
    emailVerified: boolean;
    mfaEnabled: boolean;
    createdAt: Date;
    lastLogin?: Date;
    // phone?: string;
    // phoneVerified: boolean;
    // metadata: Record<string, any>;
  };

  @ApiProperty({
    description: 'Security-related information',
  })
  security: UserSecurityInfoDto;

  @ApiProperty({
    description: 'Agencies the user belongs to',
    required: false,
    type: [UserAgencyDto],
  })
  agencies?: UserAgencyDto[];

  @ApiProperty({
    description: 'Application-specific metadata',
    required: false,
    example: { customSettings: { theme: 'dark' } },
  })
  appMetadata?: Record<string, any>;
}
