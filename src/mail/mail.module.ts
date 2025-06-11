import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter'; 
import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { ConfigService } from '@nestjs/config';
import { join } from 'path';

@Module({
  imports: [
    MailerModule.forRootAsync({
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        transport: {
          host: configService.get<string>('MAIL_HOST', 'smtp.ethereal.email'),
          port: parseInt(configService.get<string>('MAIL_PORT', '587'), 10),
          secure: configService.get<string>('MAIL_SECURE', 'false') === 'true', 
          auth: {
            user: configService.get<string>('MAIL_USER'), 
            pass: configService.get<string>('MAIL_PASS'), 
          },
        },
        defaults: {
          from: `"Tu Aplicación" <${configService.get<string>('MAIL_FROM', 'noreply@example.com')}>`,
        },
        template: {
          dir: join(__dirname, 'templates'), 
          adapter: new HandlebarsAdapter(), 
          options: {
            strict: true,
          },
        },
      }),
    }),
  ],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}