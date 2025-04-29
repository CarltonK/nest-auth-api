import { createParamDecorator, ExecutionContext } from '@nestjs/common';

export const CurrentMetadata = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();
    // Request Metadata
    const ipAddress = request.ip;
    const userAgent = request.headers['user-agent'] || '';
    return { ipAddress, userAgent };
  },
);
