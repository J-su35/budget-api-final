import { Module } from '@nestjs/common';
import { ItemsModule } from './items/items.module';
import { ConfigModule } from '@nestjs/config';
import { DbModule } from './db/db.module';

@Module({
  imports: [ItemsModule,
    ConfigModule.forRoot({ isGlobal: true }),
    DbModule
  ]
})
export class AppModule {}
