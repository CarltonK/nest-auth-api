import { Injectable } from '@nestjs/common';
import { DEFAULT_AGENCY_CONFIG } from '../utils/agency.config';

@Injectable()
export class AppConfigService {
  private readonly defaultAgencyConfig = structuredClone(DEFAULT_AGENCY_CONFIG);
  getDefaultAgencyConfig() {
    return structuredClone(this.defaultAgencyConfig);
  }
}
