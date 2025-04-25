import {
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
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
import { Response } from 'express';
import { UserInfoResponseDto } from './dto/user-info.dto';

@ApiTags('Authentication')
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
}
