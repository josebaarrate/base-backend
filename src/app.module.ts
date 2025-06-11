import { Module, ValidationPipe } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { UsersModule } from './users/users.module';
import { PrismaModule } from './prisma/prisma.module';
import { AuthModule } from './auth/auth.module';
import { ThrottlerModule, ThrottlerGuard } from '@nestjs/throttler';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD, APP_PIPE } from '@nestjs/core';
import { MailModule } from './mail/mail.module';

@Module({
  imports: [
     ThrottlerModule.forRoot([{
      ttl: 60000, // Tiempo de vida de la ventana en milisegundos (ej. 60 segundos)
      limit: 30,  // Número máximo de solicitudes en la ventana de tiempo (ttl)
    }]),
    ConfigModule.forRoot({
      isGlobal: true, // Hace ConfigModule disponible globalmente
      envFilePath: '.env',
    }),
    PrismaModule, 
    UsersModule, 
    AuthModule, MailModule
  ],
  controllers: [AppController],
  providers: [
    AppService,
    { // Configuración global para class-validator
      provide: APP_PIPE,
      useValue: new ValidationPipe({
        whitelist: true, // Elimina propiedades no definidas en el DTO
        forbidNonWhitelisted: true, // Lanza error si hay propiedades no definidas
        transform: true, // Transforma el payload a una instancia del DTO
        transformOptions: {
          enableImplicitConversion: true, // Permite conversión implícita de tipos (ej. string a number en query params)
        },
      }),
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard, // Aplica el ThrottlerGuard globalmente
    },
  ],
})
export class AppModule {}