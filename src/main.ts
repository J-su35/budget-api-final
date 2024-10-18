import { HttpAdapterHost, NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';
import { QueryFailedErrorFilter } from './filters/query-failed-error.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(new ValidationPipe())
  const { httpAdapter } = app.get(HttpAdapterHost)
  app.useGlobalFilters(new QueryFailedErrorFilter(httpAdapter))
  await app.listen(3000);
}
bootstrap();
