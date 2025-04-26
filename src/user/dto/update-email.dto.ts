import { IsEmail, IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdateEmailDto {
  @ApiProperty({
    description: 'New email address',
    example: 'new.email@example.com',
  })
  @IsEmail()
  @IsNotEmpty()
  newEmail: string;

  @ApiProperty({
    description: 'Current password for verification',
    example: 'yourSecurePassword123!',
  })
  @IsString()
  @IsNotEmpty()
  password: string;
}
