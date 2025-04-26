import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class VerifyPhoneDto {
  @ApiProperty({
    description: '6-digit verification code sent via SMS',
    example: '123456',
  })
  @IsString()
  @IsNotEmpty()
  code: string;
}
