import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Res,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response } from 'express';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { RegisterUserDto } from './dto/register.dto';
import { LoginUserDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verifyEmail.dto';
import { AuthGuard } from './auth.guard';
import { RefreshTokenDto } from './dto/refresh.dto';
import { RequestPasswordResetDto } from './dto/request-password-reset.dto';
import { PasswordResetDto } from './dto/password-reset.dto';
import { CurrentUser } from './decorators/current-user.decorator';
import { InitiateOAuthDto } from './dto/initate-oauth.dto';
import { OAuthCallbackDto } from './dto/oauth-callback.dto';
import { CurrentMetadata } from './decorators/metadata.decorator';
import { EnableMfaDto } from './dto/enable-mfa.dto';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(private readonly _authService: AuthService) {}

  /*
   * Register a new user
   */
  @Post('register')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 300000 } }) // 5 attempts per 5 minutes
  @ApiOperation({
    summary: 'Register a new user',
    description: 'Creates a new user account and sends verification email',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'User registered successfully',
    schema: {
      example: {
        message:
          'Registration successful. Please check your email for verification.',
        requiresVerification: true,
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Validation error',
    schema: {
      example: {
        statusCode: 400,
        message: 'Password is too weak',
        error: 'Bad Request',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'Email already exists',
    schema: {
      example: {
        statusCode: 409,
        message: 'Invalid registration details',
        error: 'Conflict',
      },
    },
  })
  async registerUser(
    @Res() res: Response,
    @Body() registerDto: RegisterUserDto,
    @CurrentMetadata() metadata: Record<string, any>,
  ) {
    const resp = await this._authService.registerUser(registerDto, metadata);
    return res.json(resp);
  }

  /*
   * Authenticate a user
   */
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 300000 } }) // 5 attempts per 5 minutes
  @ApiOperation({
    summary: 'Authenticate a user',
    description: 'Performs user authentication with multiple security checks',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Successful authentication',
    schema: {
      example: {
        accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        refreshToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        expiresIn: 3600,
        sessionId: '550e8400-e29b-41d4-a716-446655440000',
        mfaRequired: false,
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid request payload or credentials',
    schema: {
      example: {
        statusCode: 400,
        message: ['password must be a string'],
        error: 'Bad Request',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid credentials or expired session',
    schema: {
      example: {
        statusCode: 401,
        message: 'Invalid credentials',
        error: 'Unauthorized',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Email not verified or insufficient permissions',
    schema: {
      example: {
        statusCode: 403,
        message: 'Email not verified',
        error: 'Forbidden',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.LOCKED,
    description: 'Account temporarily locked',
    schema: {
      example: {
        statusCode: 423,
        message: 'Account temporarily locked',
        error: 'Locked',
      },
    },
  })
  async login(
    @Res() res: Response,
    @Body() loginDto: LoginUserDto,
    @CurrentMetadata() metadata: Record<string, any>,
  ) {
    const response = await this._authService.loginUser(loginDto, metadata);
    return res.json(response);
  }

  /*
   * Verify a users' email
   */
  @Get('verify-email')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: "Verify a users' email",
    description: 'Performs email verification',
  })
  @ApiQuery({ name: 'emailAddress', type: String, required: true })
  @ApiQuery({ name: 'token', type: String, required: true })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Email verified successfully',
    schema: { example: { message: 'Email verified successfully' } },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid or expired verification token',
    schema: { example: { message: 'Invalid or expired verification token' } },
  })
  async verifyEmail(
    @Res() res: Response,
    @Query() verifyEmailDto: VerifyEmailDto,
    @CurrentMetadata() metadata: Record<string, any>,
  ) {
    const response = await this._authService.verifyEmail(
      verifyEmailDto,
      metadata,
    );
    return res.json(response);
  }

  /*
   * Logout a user
   */
  @UseGuards(AuthGuard)
  @Post('logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Logout a user',
    description: 'Invalidates current session and refresh tokens',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Logged out successfully',
    schema: { example: { message: 'Logged out successfully' } },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized',
    schema: { example: { message: 'Invalid token' } },
  })
  async logout(
    @Res() res: Response,
    @CurrentUser() user: Record<string, any>,
    @CurrentMetadata() metadata: Record<string, any>,
  ) {
    const response = await this._authService.logoutUser(user, metadata);
    return res.json(response);
  }

  /*
   * Refresh an access token
   */
  @UseGuards(AuthGuard)
  @Post('refresh-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh an access token',
    description: 'Obtain a new access token using a valid refresh token',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Token refreshed successfully',
    schema: {
      example: {
        accessToken: 'new_jwt_token',
        refreshToken: 'new_refresh_token',
        expiresIn: 3600,
        sessionId: 'new_session_id',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Invalid or expired refresh token',
    schema: { example: { message: 'Invalid or expired refresh token' } },
  })
  async refreshToken(
    @Res() res: Response,
    @Body() dto: RefreshTokenDto,
    @CurrentMetadata() metadata: Record<string, any>,
  ) {
    const response = await this._authService.refreshToken(dto, metadata);
    return res.json(response);
  }

  /*
   * Request password reset
   */
  @Post('request-password-reset')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 300000 } }) // 5 attempts per 5 minutes
  @ApiOperation({
    summary: 'Request password reset',
    description: 'Initiate a password reset process for the given email',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Reset instructions sent if email exists',
    schema: {
      example: {
        message:
          'If your email is registered, you will receive reset instructions shortly.',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many reset attempts',
    schema: { example: { message: 'Too many password reset attempts' } },
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: 'Validation error',
    schema: {
      example: {
        message: 'Validation failed',
        errors: { email: 'Invalid email' },
      },
    },
  })
  async requestPasswordReset(
    @Res() res: Response,
    @Body() dto: RequestPasswordResetDto,
    @CurrentMetadata() metadata: Record<string, any>,
  ) {
    const response = await this._authService.requestPasswordReset(
      dto.emailAddress,
      metadata,
    );
    return res.json(response);
  }

  /*
   * Reset password with token
   */
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @Throttle({ default: { limit: 5, ttl: 300000 } }) // 5 attempts per 5 minutes
  @ApiOperation({
    summary: 'Reset password',
    description: 'Reset user password using a valid reset token',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Password reset successful',
    schema: {
      example: {
        message:
          'Password has been reset successfully. Please login with your new password.',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid or expired reset token',
    schema: { example: { message: 'Invalid or expired reset token' } },
  })
  @ApiResponse({
    status: HttpStatus.UNPROCESSABLE_ENTITY,
    description: 'Validation error or weak password',
    schema: {
      example: {
        message: 'Password is too weak',
        feedback: {
          warning: 'This is a very common password',
          suggestions: ['Add more words', 'Avoid common phrases'],
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.TOO_MANY_REQUESTS,
    description: 'Too many reset attempts',
    schema: {
      example: { message: 'Too many reset attempts. Please try again later.' },
    },
  })
  async resetPassword(
    @Res() res: Response,
    @Body() dto: PasswordResetDto,
    @CurrentMetadata() metadata: Record<string, any>,
  ) {
    const response = await this._authService.resetPassword(dto, metadata);
    return res.json(response);
  }

  /*
   * Initate OAuth flow
   */
  @Get('oauth/initiate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Initiate OAuth flow',
    description: 'Redirects to the specified OAuth provider for authentication',
  })
  @ApiQuery({ type: InitiateOAuthDto, name: 'provider', required: true })
  @ApiResponse({
    status: HttpStatus.FOUND,
    description: 'Redirect to OAuth provider',
    headers: {
      Location: {
        description: 'OAuth provider URL',
        example: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=...',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Invalid or disabled OAuth provider',
    schema: {
      example: {
        message: 'Invalid or disabled OAuth provider',
      },
    },
  })
  async initiateOAuth(
    @Query() { provider }: InitiateOAuthDto,
    @Res() res: Response,
  ) {
    const url = await this._authService.initiateOauth(provider);
    res.redirect(url);
  }

  /*
   * OAuth callback endpoint
   */
  @Get('oauth/callback')
  @ApiOperation({
    summary: 'OAuth callback handler',
    description:
      'Handles the callback from OAuth provider after authentication',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'OAuth authentication successful',
    schema: {
      example: {
        access_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        refresh_token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        expires_in: 3600,
        session_id: 'abc123-def456-ghi789',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'OAuth error occurred',
    schema: {
      examples: {
        OAuthError: {
          value: {
            error: 'OAuth error: access_denied',
          },
        },
        StateMismatch: {
          value: {
            error: 'Invalid state or missing code',
          },
        },
        InvalidProvider: {
          value: {
            error: 'Invalid OAuth provider',
          },
        },
        TokenError: {
          value: {
            error: 'Failed to obtain access token',
          },
        },
        UserInfoError: {
          value: {
            error: 'Failed to obtain user information',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error during OAuth processing',
  })
  async handleOAuthCallback(
    @Query() query: OAuthCallbackDto,
    @Res() res: Response,
  ) {
    const result = await this._authService.handleOAuthCallback(query);
    return res.json(result);
  }

  /*
   * Enable MFA
   */
  @Post('mfa/enable')
  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard)
  @ApiOperation({
    summary: 'Enable multi-factor authentication',
    description: 'Initiates MFA setup for the authenticated user',
  })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'MFA setup initiated successfully',
    schema: {
      oneOf: [
        {
          properties: {
            message: { type: 'string', example: 'MFA setup initiated' },
            secret: { type: 'string', example: 'JBSWY3DPEHPK3PXP' },
            qrCode: { type: 'string', example: '<svg>...</svg>' },
          },
        },
        {
          properties: {
            message: { type: 'string', example: 'MFA setup initiated' },
          },
        },
      ],
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Validation error or business rule violation',
    schema: {
      examples: {
        InvalidType: {
          value: { message: 'Invalid MFA type' },
        },
        PhoneNotVerified: {
          value: { message: 'Phone number not verified' },
        },
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.INTERNAL_SERVER_ERROR,
    description: 'Internal server error during MFA setup',
  })
  async enableMfa(
    @Body() dto: EnableMfaDto,
    @CurrentUser() user: Record<string, any>,
    @Res() res: Response,
  ) {
    const result = await this._authService.enableMfa(user, dto);
    return res.json(result);
  }
}
