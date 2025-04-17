import {
  INestApplication,
  Injectable,
  OnModuleDestroy,
  OnModuleInit,
  Logger,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaClient } from '@prisma/client';
import { exec } from 'child_process';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly _logger = new Logger(PrismaService.name);

  constructor(configService: ConfigService) {
    super({
      datasources:
        configService.get('NODE_ENV') != 'local'
          ? { db: { url: configService.get<string>('DATABASE_URL') } }
          : undefined,
      log: [
        { level: 'info', emit: 'stdout' },
        { level: 'query', emit: 'stdout' },
        { level: 'warn', emit: 'stdout' },
        { level: 'error', emit: 'stdout' },
      ],
    });

    // Context binding
    this.loggingMiddleware = this.loggingMiddleware.bind(this);
  }

  async onModuleInit() {
    await this.$connect();
    this._logger.log('Database connected');
    this.$use(this.loggingMiddleware);
  }

  async onModuleDestroy() {
    await this.$disconnect();
  }

  enableShutdownHooks(app: INestApplication) {
    process.on('beforeExit', () => {
      app.close();
    });
  }

  async runMigrations() {
    return new Promise((resolve) => {
      exec(
        'npm run migrations:prod',
        { maxBuffer: 1024 * 500 },
        (error, stdout) => {
          if (error) {
            this._logger.error(`Migration error: ${error.message}`);
          } else if (stdout) {
            this._logger.error(`Migration output: ${stdout}`);
          }
          resolve(stdout ? true : false);
        },
      );
    });
  }

  loggingMiddleware(params: any, next: any) {
    const before = Date.now();
    const result = next(params);
    const after = Date.now();

    const log = `Query ${params.model}.${params.action} took ${after - before}ms`;
    this._logger.debug(log);
    return result;
  }
}
