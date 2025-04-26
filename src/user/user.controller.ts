import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Inject,
  Put,
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
import { UpdateUserInfoDto } from './dto/update-user-info.dto';

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
    description: 'No valid fields to update',
  })
  @ApiResponse({
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
}
