import { IsNotEmpty, IsString, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdatePhoneDto {
  @ApiProperty({
    description: 'New phone number in E.164 format',
    example: '+14155552671',
  })
  @IsString()
  @Matches(/^\+[1-9]\d{10,14}$/, {
    message: 'Phone number must be in E.164 format (e.g. +14155552671)',
  })
  newPhone: string;

  @ApiProperty({
    description: 'Current password for verification',
    example: 'yourSecurePassword123!',
  })
  @IsString()
  @IsNotEmpty()
  password: string;
}
