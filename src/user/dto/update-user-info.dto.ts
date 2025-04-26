import { IsObject, IsOptional, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateUserInfoDto {
  @ApiProperty({
    description: 'User first name',
    required: false,
    example: 'John',
  })
  @IsOptional()
  @IsString()
  firstName?: string;

  @ApiProperty({
    description: 'User last name',
    required: false,
    example: 'Doe',
  })
  @IsOptional()
  @IsString()
  lastName?: string;

  @ApiProperty({
    description: 'User metadata object',
    required: false,
    example: { theme: 'dark', language: 'en' },
  })
  @IsOptional()
  @IsObject()
  metadata?: Record<string, any>;
}
