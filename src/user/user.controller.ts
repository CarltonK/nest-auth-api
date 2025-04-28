import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Post,
  Put,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentUser } from './../auth/decorators/current-user.decorator';
import { AuthGuard } from './../auth/auth.guard';
import { Response, Request } from 'express';
import { UserInfoResponseDto } from './dto/user-info.dto';
import { UpdateUserInfoDto } from './dto/update-user-info.dto';
import { UpdateEmailDto } from './dto/update-email.dto';
import { VerifyEmailUpdateDto } from './dto/verify-email-update.dto';
import { UpdatePhoneDto } from './dto/update-phone.dto';
import { VerifyPhoneDto } from './dto/verify-phone.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';

@ApiTags('Users')
@Controller('users')
export class UserController {
  constructor(
    @Inject(UserService) private readonly _userService: UserService,
  ) {}

  /*
   * Get authenticated user information
   */
  @UseGuards(AuthGuard)
  @Get('me')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Get authenticated user information',
    description:
      'Retrieves complete profile, security information, and active sessions for the authenticated user',
  })
  @ApiBearerAuth()
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User information retrieved successfully',
    type: UserInfoResponseDto,
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized - Invalid or missing authentication token',
    schema: {
      example: {
        message: 'Authorization failed',
      },
    },
  })
  async getUserInfo(
    @Res() res: Response,
    @CurrentUser() user: Record<string, any>,
  ) {
    const response = await this._userService.getUserInfo(user);
    return res.json(response);
  }

  /*
   * Update an authenticated users' information
   */
  @Put('me')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Update user information',
    description:
      'Updates personal information and metadata for the authenticated user',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User information updated successfully',
    schema: {
      example: {
        message: 'User information updated successfully',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'No valid fields to update',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized - Invalid or missing authentication token',
  })
  async updateUserInfo(
    @Res() res: Response,
    @CurrentUser() user: Record<string, any>,
    @Body() updateData: UpdateUserInfoDto,
  ) {
    const response = await this._userService.updateUserInfo(user, updateData);
    return res.json(response);
  }

  /*
   * Initiate an email update for an authenticated user
   */
  @Put('me/email')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Initiate email update',
    description:
      'Starts the email update process by verifying password and sending verification email',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Verification email sent successfully',
    schema: {
      example: {
        message: 'Please check your new email for verification instructions',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Email already in use / Invalid request format',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid password / Invalid credentials',
  })
  async updateEmail(
    @Res() res: Response,
    @Body() updateData: UpdateEmailDto,
    @CurrentUser() user: Record<string, any>,
  ) {
    const response = await this._userService.initiateEmailUpdate(
      user,
      updateData,
    );
    return res.json(response);
  }

  /*
   * Verify an email update for a user
   */
  @Get('me/verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Verify email update',
    description:
      'Confirms email change using verification token sent to new email',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Email updated successfully',
    schema: {
      example: {
        message:
          'Email updated successfully. Please log in with your new email.',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid or expired verification token',
  })
  async verifyEmailUpdate(
    @Res() res: Response,
    @Query() { token }: VerifyEmailUpdateDto,
  ) {
    const response = await this._userService.verifyEmailUpdate(token);
    return res.json(response);
  }

  /*
   * Initiate a phone update for an authenticated user
   */
  @Put('me/phone')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Initiate phone number update',
    description:
      'Starts phone number update process with password verification and SMS code',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Verification code sent successfully',
    schema: {
      example: {
        message: 'Verification code sent to your new phone number',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid phone format/Phone number is already in use',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Current password is incorrect',
  })
  async updatePhone(
    @Res() res: Response,
    @Body() updateData: UpdatePhoneDto,
    @CurrentUser() user: Record<string, any>,
  ) {
    const response = await this._userService.initiatePhoneUpdate(
      user,
      updateData,
    );
    return res.json(response);
  }

  /*
   * Verify a phone number update for a user
   */
  @Get('me/verify-phone')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Verify phone number update',
    description: 'Confirms phone number change using SMS verification code',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Phone number verified successfully',
    schema: {
      example: {
        message: 'Phone number verified successfully',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid or expired verification code',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Authentication required',
  })
  async verifyPhoneUpdate(
    @Res() res: Response,
    @Query() { code }: VerifyPhoneDto,
    @CurrentUser() user: Record<string, any>,
  ) {
    const response = await this._userService.verifyPhoneUpdate(user, code);
    return res.json(response);
  }

  /*
   * Update an authenticated users' password
   */
  @Post('me/password')
  @UseGuards(AuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Update the password for an authenticated user',
    description: 'Changes the password for an authenticated user',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Password updated successfully',
    schema: {
      example: {
        message: 'Password updated successfully',
        accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        expiresIn: 3600,
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'New password must be different from current password',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description:
      'This password has been found in data breaches. Please choose a different password.',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description:
      'Password has been used recently. Please choose a different password.',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'New password must be different from current password',
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Current password is incorrect',
  })
  async updatePassword(
    @Req() request: Request,
    @Res() res: Response,
    @Body() dto: UpdatePasswordDto,
    @CurrentUser() user: Record<string, any>,
  ) {
    // Request Metadata
    const ipAddress = request.ip;
    const userAgent = request.headers['user-agent'] || '';
    const metadata = { ipAddress, userAgent };

    const response = await this._userService.passwordUpdate(
      dto,
      user,
      metadata,
    );
    return res.json(response);
  }
}
