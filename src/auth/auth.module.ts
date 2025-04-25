import { Module } from '@nestjs/common';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { HttpModule } from '@nestjs/axios';
import { PrismaModule } from './../prisma/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { JwtService } from './jwt.service';
import { createOAuthProviders } from './providers/oauth.providers';
import { OAuthService } from './oauth.service';

@Module({
  imports: [
    ConfigModule,
    HttpModule,
    PrismaModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('jwt.accessSecret'),
        signOptions: {
          expiresIn: configService.get<number>('jwt.accessExpiry'),
        },
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    AuthGuard,
    JwtService,
    {
      provide: 'OAUTH_PROVIDERS',
      useFactory: createOAuthProviders,
      inject: [ConfigService],
    },
    OAuthService,
  ],
  exports: [AuthGuard, JwtService],
})
export class AuthModule {}
