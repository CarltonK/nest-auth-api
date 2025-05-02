import { IsString, IsNotEmpty, IsIn } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class EnableMfaDto {
  @ApiProperty({
    description: 'Type of MFA to enable',
    example: 'totp',
    enum: ['totp', 'sms', 'email'],
  })
  @IsString()
  @IsNotEmpty()
  @IsIn(['totp', 'sms', 'email'])
  type: 'totp' | 'sms' | 'email';
}
