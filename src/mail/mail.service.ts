import { MailerService } from '@nestjs-modules/mailer';
import { Injectable, Logger } from '@nestjs/common';
import { User } from '@prisma/client';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly mailerService: MailerService) {}

  async sendUserVerificationEmail(user: User, token: string, expiresInMinutes: number) {
    const frontendUrl = process.env.CLIENT_URL || 'http://localhost:3001'; 
    const verificationUrl = `${frontendUrl}/verify-email?token=${token}`;

    try {
      await this.mailerService.sendMail({
        to: user.email,
        subject: 'Bienvenido! Confirma tu Email',
        template: './email-verification', 
        context: {
          name: user.firstName || user.email,
          url: verificationUrl,
          expiration: `${expiresInMinutes} minutos`,
        },
      });
      this.logger.log(`Email de verificación enviado a ${user.email}. URL: ${verificationUrl}`);
    } catch (error) {
      this.logger.error(`Error enviando email de verificación a ${user.email}`, error.stack);
    }
  }

  async sendPasswordResetEmail(user: User, token: string, expiresInMinutes: number) {
    const frontendUrl = process.env.CLIENT_URL || 'http://localhost:3001';
    const resetUrl = `${frontendUrl}/reset-password?token=${token}`;

    try {
      await this.mailerService.sendMail({
        to: user.email,
        subject: 'Restablecimiento de Contraseña',
        template: './password-reset',
        context: {
          name: user.firstName || user.email,
          url: resetUrl,
          expiration: `${expiresInMinutes} minutos`,
        },
      });
      this.logger.log(`Email de reseteo de contraseña enviado a ${user.email}. URL: ${resetUrl}`);
    } catch (error) {
      this.logger.error(`Error enviando email de reseteo a ${user.email}`, error.stack);
    }
  }
}