import { Controller, Get, Res } from '@nestjs/common';
import { AppService } from './app.service';
import { ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { Response } from 'express';

@ApiTags('App')
@Controller()
export class AppController {
  constructor(private readonly _appService: AppService) {}

  @Get('/health')
  @ApiOperation({ summary: 'System health check' })
  @ApiResponse({
    status: 200,
    description: 'Health status report',
    schema: {
      example: {
        status: 'up',
        timestamp: '2023-01-01T00:00:00.000Z',
        uptime: 12345,
        checks: {
          api: { status: 'up' },
          database: {
            status: 'up',
            responseTime: '5ms',
          },
        },
      },
    },
  })
  @ApiResponse({
    status: 503,
    description: 'Service unavailable',
    schema: {
      example: {
        status: 'down',
        timestamp: '2023-01-01T00:00:00.000Z',
        checks: {
          api: { status: 'up' },
          database: {
            status: 'down',
            error: 'Connection refused',
          },
        },
      },
    },
  })
  async healthCheck(@Res() res: Response) {
    const response = await this._appService.healthCheck();
    return res.json(response);
  }
}
