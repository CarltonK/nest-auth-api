import { ApiProperty } from '@nestjs/swagger';

export class OAuthCallbackDto {
  @ApiProperty({
    description: 'OAuth state parameter for CSRF protection',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  state: string;

  @ApiProperty({
    description: 'Authorization code from OAuth provider',
    example: '4/0Adeu5BV3Fwq8d4L2...',
    required: false,
  })
  code?: string;

  @ApiProperty({
    description: 'Error from OAuth provider',
    example: 'access_denied',
    required: false,
  })
  error?: string;

  @ApiProperty({
    description: 'Error description from OAuth provider',
    name: 'error_description',
    required: false,
  })
  errorDescription?: string;
}
