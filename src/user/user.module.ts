import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { PrismaModule } from './../prisma/prisma.module';
import { AuthModule } from './../auth/auth.module';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [PrismaModule, AuthModule, HttpModule],
  controllers: [UserController],
  providers: [UserService],
})
export class UserModule {}
