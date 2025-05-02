import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class GenerateBackupCodesDto {
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
