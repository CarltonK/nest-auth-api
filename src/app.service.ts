import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  livenessCheck(): string {
    return 'GPS API is up and running!';
  }
}
