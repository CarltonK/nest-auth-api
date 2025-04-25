import { Inject, Injectable, Logger } from '@nestjs/common';
import { PrismaService } from './prisma/prisma.service';

@Injectable()
export class AppService {
  private readonly _logger = new Logger(AppService.name);
  constructor(
    @Inject(PrismaService) private readonly _prismaService: PrismaService,
  ) {}

  async healthCheck() {
    const uptime = process.uptime(); // seconds

    const healthCheck = {
      status: 'up',
      timestamp: new Date().toISOString(),
      uptime,
      checks: {
        api: {
          status: 'up',
        },
        database: {
          status: 'down', // default to down
          responseTime: `0ms`,
          error: null,
        },
      },
    };

    try {
      // Database health check
      const dbStart = Date.now();
      await this._prismaService.$queryRaw`SELECT 1`;
      const dbEnd = Date.now();

      healthCheck.checks.database = {
        status: 'up',
        responseTime: `${dbEnd - dbStart}ms`,
        error: undefined,
      };
    } catch (error) {
      this._logger.error(
        'Database health check failed',
        error.stack || error.message,
      );
      healthCheck.status = 'down';
      healthCheck.checks.database.error = error.message;
    }

    return healthCheck;
  }
}
