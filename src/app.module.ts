import { MiddlewareConsumer, Module, NestModule, RequestMethod } from '@nestjs/common';
import { ItemsModule } from './items/items.module';
import { ConfigModule } from '@nestjs/config';
import { DbModule } from './db/db.module';
import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { LoginLoggerMiddleware } from './middlewares/login-logger.middleware';

@Module({
  imports: [ItemsModule,
    ConfigModule.forRoot({ isGlobal: true }),
    DbModule,
    UsersModule,
    AuthModule
  ]
})
export class AppModule implements NestModule { 
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(LoginLoggerMiddleware)
    .forRoutes({ path: '*login*', method: RequestMethod.POST})
  }
}
