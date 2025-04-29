import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { PrismaModule } from './../prisma/prisma.module';
import { AuthModule } from './../auth/auth.module';
import { HttpModule } from '@nestjs/axios';
import { AppConfigModule } from './../app-config/app-config.module';

@Module({
  imports: [PrismaModule, AuthModule, HttpModule, AppConfigModule],
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}
