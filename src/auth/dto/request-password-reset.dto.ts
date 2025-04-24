import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class RequestPasswordResetDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'The email address to send reset instructions to',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
