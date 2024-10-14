import { Module } from '@nestjs/common';
import { ItemsModule } from './items/items.module';
import { ConfigModule } from '@nestjs/config';
import { DbModule } from './db/db.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [ItemsModule,
    ConfigModule.forRoot({ isGlobal: true }),
    DbModule,
    UsersModule
  ]
})
export class AppModule {}
