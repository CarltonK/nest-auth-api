import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, MinLength, IsNotEmpty } from 'class-validator';

export class LoginUserDto {
  @ApiProperty({
    description: 'User email address',
    example: 'user@example.com',
    format: 'email',
    required: true,
  })
  @IsEmail()
  @IsNotEmpty()
  emailAddress: string;

  @ApiProperty({
    description: 'User password (min 8 characters)',
    minLength: 8,
    example: 'Str0ngP@ssw0rd!',
    required: true,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  password: string;
}
