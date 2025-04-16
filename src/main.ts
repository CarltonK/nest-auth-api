import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { json, urlencoded } from 'express';
import helmet from 'helmet';
import { ConfigService } from '@nestjs/config';
import {
  BadRequestException,
  ValidationError,
  ValidationPipe,
} from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    rawBody: true,
    logger: ['log', 'error', 'warn', 'debug', 'verbose'],
  });
  app.use(json({ limit: '5mb' })); // Set global max body size to 5mb
  app.use(urlencoded({ limit: '5mb', extended: true }));

  /*
   * Global Pipes
   */
  // 1. Validation Pipe
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      exceptionFactory: (validationErrors: ValidationError[] = []) => {
        const getPrettyClassValidatorErrors = (
          validationErrors: ValidationError[],
          parentProperty = '',
        ): Array<{ property: string; errors: string[] }> => {
          const errors = [];

          const getValidationErrorsRecursively = (
            validationErrors: ValidationError[],
            parentProperty = '',
          ) => {
            for (const error of validationErrors) {
              const propertyPath = parentProperty
                ? `${parentProperty}.${error.property}`
                : error.property;

              if (error.constraints) {
                errors.push({
                  property: propertyPath,
                  errors: Object.values(error.constraints),
                });
              }

              if (error.children?.length) {
                getValidationErrorsRecursively(error.children, propertyPath);
              }
            }
          };

          getValidationErrorsRecursively(validationErrors, parentProperty);

          return errors;
        };

        const errors = getPrettyClassValidatorErrors(validationErrors);

        return new BadRequestException({
          message: 'Validation error',
          errors: errors,
        });
      },
    }),
  );

  /*
   * Security
   */
  app.use(helmet()); // Helmet
  app.enableCors(); // Cors

  const configService = app.get(ConfigService);
  await app.listen(configService.get('PORT'));
}
bootstrap();
