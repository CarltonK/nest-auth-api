import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UpdatePasswordDto {
  @ApiProperty({
    description: 'Current password for verification',
    example: 'yourSecurePassword123!',
  })
  @IsString()
  @IsNotEmpty()
  currentPassword: string;

  @ApiProperty({
    description: 'Current password for verification',
    example: 'yourSecurePassword123!',
  })
  @IsString()
  @IsNotEmpty()
  newPassword: string;
}
