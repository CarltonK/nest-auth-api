import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { JwtService } from './jwt.service';

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(@Inject(JwtService) private readonly _jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException({
        message: 'Authorization failed: Bearer token not found',
      });
    }

    try {
      const payload = await this._jwtService.verifyToken(token);
      request.user = payload;
      return true;
    } catch (error) {
      const message = this.getErrorMessage(error);
      throw new UnauthorizedException({ message });
    }
  }

  private extractTokenFromHeader(request: Request): string | null {
    const authHeader = request.headers.authorization;
    if (!authHeader) return null;

    const [type, token] = authHeader.split(' ');
    return type === 'Bearer' ? token : null;
  }

  private getErrorMessage(error: any): string {
    if (error.name === 'TokenExpiredError') {
      return 'Authorization failed: Token expired';
    }
    if (error.name === 'JsonWebTokenError') {
      return 'Authorization failed: Invalid token';
    }
    return 'Authorization failed: Unknown error';
  }
}
