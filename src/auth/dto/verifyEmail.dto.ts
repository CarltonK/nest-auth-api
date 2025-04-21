import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class VerifyEmailDto {
  @IsEmail()
  @IsNotEmpty()
  emailAddress: string;

  @IsString()
  @IsNotEmpty()
  token: string;
}
