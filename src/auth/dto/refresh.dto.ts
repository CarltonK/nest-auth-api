import { ApiProperty } from '@nestjs/swagger';
import { IsString, IsNotEmpty } from 'class-validator';

export class RefreshTokenDto {
  @ApiProperty({
    description: 'Refresh Token',
    required: true,
  })
  @IsString()
  @IsNotEmpty()
  refreshToken: string;
}
