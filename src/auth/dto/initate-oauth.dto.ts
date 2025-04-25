import { IsString, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class InitiateOAuthDto {
  @ApiProperty({
    description: 'OAuth provider name',
    example: 'google',
    enum: ['google'],
    // enum: ['google', 'facebook', 'github'],
  })
  @IsString()
  @IsNotEmpty()
  provider: string;
}
