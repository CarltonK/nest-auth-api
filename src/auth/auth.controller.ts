import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Query,
  Req,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { Response, Request } from 'express';
import { ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { RegisterUserDto } from './dto/register.dto';
import { LoginUserDto } from './dto/login.dto';
import { VerifyEmailDto } from './dto/verifyEmail.dto';

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
    @Req() request: Request,
    @Res() res: Response,
    @Body() registerDto: RegisterUserDto,
  ) {
    // Request Metadata
    const ipAddress = request.ip;
    const userAgent = request.headers['user-agent'] || '';
    const metadata = { ipAddress, userAgent };

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
    summary: 'Authenticate user',
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
    @Req() request: Request,
    @Res() res: Response,
    @Body() loginDto: LoginUserDto,
  ) {
    // Request Metadata
    const ipAddress = request.ip;
    const userAgent = request.headers['user-agent'] || '';
    const metadata = { ipAddress, userAgent };

    const response = await this._authService.loginUser(loginDto, metadata);
    return res.json(response);
  }

  /*
   * Verify a users' email
   */
  @Get('verify-email')
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
    @Req() request: Request,
    @Res() res: Response,
    @Query() verifyEmailDto: VerifyEmailDto,
  ) {
    // Request Metadata
    const ipAddress = request.ip;
    const userAgent = request.headers['user-agent'] || '';
    const metadata = { ipAddress, userAgent };

    const response = await this._authService.verifyEmail(
      verifyEmailDto,
      metadata,
    );
    return res.json(response);
  }
}
