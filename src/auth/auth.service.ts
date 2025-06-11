import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  InternalServerErrorException,
  ForbiddenException,
  Logger,
  BadRequestException,
  HttpStatus,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import * as crypto from 'crypto';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';
import { Prisma, User } from '@prisma/client';
import { Response } from 'express';
import { UsersService } from '../users/users.service'; 
import { AccessTokenPayload } from './interfaces/AccessTokenPayload.inteface';
import { RefreshTokenPayload } from './interfaces/RefreshTokenPayload.inteface';
import { MailService } from 'src/mail/mail.service';
import { v4 as uuidv4 } from 'uuid';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { MobileLoginSuccessResponse, MobileRefreshSuccessResponse, UserProfile, WebLoginSuccessResponse, WebRefreshSuccessResponse } from './auth.types';
import type { ClientType } from '../common/decorators/client-type.decorator';

@Injectable()
export class AuthService {
    private readonly logger = new Logger(AuthService.name);
    private readonly MAX_ACTIVE_SESSIONS: number;
    private readonly JWT_REFRESH_EXPIRATION_DAYS: number;

    constructor(
        private readonly prisma: PrismaService,
        private readonly jwtService: JwtService,
        private readonly configService: ConfigService,
        private readonly usersService: UsersService,
        private readonly mailService: MailService,
    ) {
        this.MAX_ACTIVE_SESSIONS = parseInt(this.configService.get<string>('MAX_ACTIVE_SESSIONS', '5'), 10);
        this.JWT_REFRESH_EXPIRATION_DAYS = parseInt(this.configService.get<string>('JWT_REFRESH_EXPIRATION_DAYS', '7'), 10);
    }

    private async hashPassword(password: string): Promise<string> {
        const salt = await bcrypt.genSalt(10);
        return bcrypt.hash(password, salt);
    }

    private hashToken(token: string): string {
        return crypto.createHash('sha256').update(token).digest('hex');
    }

    private async generateAccessToken(user: User, sessionId: number): Promise<string> {
        const payload: AccessTokenPayload = {
            userId: user.id,
            sessionId: sessionId,
            roleId: user.roleId || undefined,
        };
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_ACCESS_SECRET'),
            expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRATION'),
        });
    }

    private async generateRefreshToken(user: User, sessionId: number): Promise<string> {
        const payload: RefreshTokenPayload = { userId: user.id, sessionId: sessionId };
        return this.jwtService.sign(payload, {
            secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            expiresIn: `${this.JWT_REFRESH_EXPIRATION_DAYS}d`,
        });
    }

    private setTokenCookies(res: Response, accessToken: string, refreshToken: string): void {
        const isProduction = this.configService.get<string>('NODE_ENV') === 'production';
        const accessExp = this.configService.get<string>('JWT_ACCESS_EXPIRATION'); // "15m"
        const refreshExpDays = this.JWT_REFRESH_EXPIRATION_DAYS;

        const getMilliseconds = (timeStr: string): number => {
            const unit = timeStr.slice(-1);
            const value = parseInt(timeStr.slice(0, -1), 10);
            if (unit === 'm') return value * 60 * 1000;
            if (unit === 'h') return value * 60 * 60 * 1000;
            if (unit === 'd') return value * 24 * 60 * 60 * 1000;
            return value;
        }

        res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'lax',
        //path: '/',
        maxAge: getMilliseconds(accessExp),
        });

        res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: isProduction,
        sameSite: 'strict',
        maxAge: refreshExpDays * 24 * 60 * 60 * 1000,
        });
    }

    public clearTokenCookies(res: Response): void {
        const isProduction = this.configService.get<string>('NODE_ENV') === 'production';
        const cookieOptions = { httpOnly: true, secure: isProduction, expires: new Date(0) };
        res.cookie('accessToken', '', { ...cookieOptions, sameSite: 'lax' });
        res.cookie('refreshToken', '', { ...cookieOptions, sameSite: 'strict' });
    }

    async register(registerUserDto: RegisterDto): Promise<Omit<User, 'passwordHash' | 'emailVerificationToken' | 'emailVerificationTokenExpiresAt' | 'passwordResetToken' | 'passwordResetTokenExpiresAt'>> {
        const {
            email,
            password,
            firstName,
            lastName,
            profileImageUrl,
            roleId,
        } = registerUserDto;

        const existingUser = await this.prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            throw new ConflictException('El email ya está registrado.');
        }

        const passwordHash = await this.hashPassword(password);

        const emailVerificationToken = uuidv4();
        const hashedEmailVerificationToken = this.hashToken(emailVerificationToken);
        const emailVerificationTokenExpiresInMinutes = 60 * 24;
        const emailVerificationTokenExpiresAt = new Date(
            Date.now() + emailVerificationTokenExpiresInMinutes * 60 * 1000,
        );

        const dataForCreate: Prisma.UserCreateInput = {
            email,
            passwordHash,
            firstName: firstName || null,
            lastName: lastName || null,
            profileImageUrl: profileImageUrl || null,

            isActive: true,
            emailVerified: false,
            emailVerificationToken: hashedEmailVerificationToken,
            emailVerificationTokenExpiresAt,

            ...(roleId && { role: { connect: { id: roleId } } }),
        };

        try {
            const user = await this.prisma.user.create({
                data: dataForCreate,
            });

            this.mailService.sendUserVerificationEmail(user, emailVerificationToken, emailVerificationTokenExpiresInMinutes)
                .catch(err => this.logger.error('Fallo al enviar email de verificación en segundo plano', err.stack));

            const { passwordHash: _, emailVerificationToken: __, emailVerificationTokenExpiresAt: ___, passwordResetToken, passwordResetTokenExpiresAt, ...result } = user;
            return result;

        } catch (error: any) {
            this.logger.error(`Error en registro para ${email}: ${error.message}`, error.stack);
            if (error.code === 'P2002' && error.meta?.target?.includes('emailVerificationToken')) {
                throw new InternalServerErrorException('Error generando token de verificación, intenta de nuevo.');
            }
            if (error.code === 'P2025') {
                this.logger.error(`Error de Prisma P2025: Uno de los IDs para conectar (rol, industria, provincia, ciudad) no existe. Input: ${JSON.stringify({roleId})}`);
                throw new BadRequestException('Uno de los valores proporcionados para rol, industria, provincia o ciudad no es válido.');
            }

            if (error instanceof Prisma.PrismaClientValidationError && error.message.includes("Argument `preferredDays` must not be null")) {
                this.logger.error(`Error de validación de Prisma: Campos obligatorios como preferredDays no pueden ser null. DTO: ${JSON.stringify(registerUserDto)}`);
                throw new BadRequestException('Faltan campos obligatorios o tienen un formato incorrecto para las preferencias.');
            }
            throw new InternalServerErrorException('No se pudo registrar el usuario.');
        }
    }

    async login(
        loginDto: LoginDto,
        ipAddress: string,
        userAgent: string,
        clientType: ClientType,
        res?: Response,
    ): Promise<WebLoginSuccessResponse | MobileLoginSuccessResponse> { 
        const { email, password } = loginDto;
        const user = await this.usersService.findByEmail(email);

        if (!user) {
            throw new UnauthorizedException('Credenciales inválidas.');
        }

        if (!user.isActive) {
            throw new ForbiddenException('La cuenta está desactivada.');
        }

        const isPasswordMatching = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordMatching) {
            throw new UnauthorizedException('Credenciales inválidas.');
        }

        const userSessions = await this.prisma.userSession.findMany({
            where: { userId: user.id },
            orderBy: { createdAt: 'asc' },
        });

        if (userSessions.length >= this.MAX_ACTIVE_SESSIONS) {
            const oldestSession = userSessions[0];
            this.logger.log(`Usuario ${user.id} alcanzó límite de sesiones. Eliminando sesión ${oldestSession.id}`);

            await this.prisma.userSession.delete({ where: { id: oldestSession.id } });
        }

        const newSession = await this.prisma.userSession.create({
            data: { userId: user.id, ipAddress, userAgent },
        });

        const accessToken = await this.generateAccessToken(user, newSession.id);
        const refreshToken = await this.generateRefreshToken(user, newSession.id);

        const hashedRefreshToken = this.hashToken(refreshToken);
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + this.JWT_REFRESH_EXPIRATION_DAYS);

        await this.prisma.refreshToken.create({
            data: {
                userId: user.id,
                tokenHash: hashedRefreshToken,
                expiresAt,
                
                userSessionId: newSession.id,
            },
        });

        const userProfileData: UserProfile | null = await this.usersService.findByIdWithProfileCompletion(user.id);

        if (!userProfileData) {
            this.logger.error(`No se pudo obtener el perfil completo para el usuario ${user.id} después del login.`);
            throw new InternalServerErrorException('Error al procesar la información del usuario.');
        }

        if (clientType === 'mobile') {
            this.logger.log(`Login móvil exitoso para ${user.email}`);
            return {
                accessToken,
                refreshToken,
                user: userProfileData,
            };
        } else { 
            if (!res) {
                this.logger.error('Response object (res) no provisto para login web.');
                throw new InternalServerErrorException('Error de configuración del servidor para login web.');
            }
            this.logger.log(`Login web exitoso para ${user.email}`);
            this.setTokenCookies(res, accessToken, refreshToken);
            return {
                statusCode: HttpStatus.OK,
                message: 'Login exitoso.',
                data: { user: userProfileData },
            };
        }
    }

    async verifyEmail(token: string): Promise<{ message: string }> {
        if (!token) {
            throw new BadRequestException('Token de verificación no proporcionado.');
        }
        const hashedToken = this.hashToken(token);

        const user = await this.prisma.user.findUnique({
            where: { emailVerificationToken: hashedToken },
        });

        if (!user) {
            throw new BadRequestException('Token de verificación inválido o ya utilizado.');
        }

        if (user.emailVerified) {
            return { message: 'El email ya ha sido verificado.' };
        }

        if (new Date() > new Date(user.emailVerificationTokenExpiresAt)) {
            throw new BadRequestException('El token de verificación ha expirado.');
        }

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                emailVerified: true,
                emailVerificationToken: null,
                emailVerificationTokenExpiresAt: null,
            },
        });

        return { message: 'Email verificado exitosamente.' };
    }
    
    async sendVerifyEmail(userId: number): Promise<{ message: string }> {
        const user = await this.prisma.user.findUnique({ where: { id:userId } });
        if (!user) {
            throw new ConflictException('Usuario no encontrado.');
        }

        const emailVerificationToken = uuidv4();
        const hashedEmailVerificationToken = this.hashToken(emailVerificationToken);
        const emailVerificationTokenExpiresInMinutes = 60 * 24;
        const emailVerificationTokenExpiresAt = new Date(
            Date.now() + emailVerificationTokenExpiresInMinutes * 60 * 1000,
        );

        try {
            await this.prisma.user.update({
                where: { id: userId },
                data: {
                    emailVerificationToken: hashedEmailVerificationToken,
                    emailVerificationTokenExpiresAt,
                    emailVerified: false, 
                },
            });

            this.mailService.sendUserVerificationEmail(
                user,
                emailVerificationToken,
                emailVerificationTokenExpiresInMinutes
            ).catch(err =>
                this.logger.error('Fallo al enviar email de verificación en segundo plano', err.stack)
            );

            return { message: 'Correo de verificación enviado correctamente.' };
        } catch(error: any) {
            this.logger.error(`Error al reenviar verificación a ${user.email}: ${error.message}`, error.stack);

            if (error.code === 'P2025') {
                throw new BadRequestException('No se pudo actualizar el usuario. ¿Existe aún?');
            }

            throw new InternalServerErrorException('Error interno al reenviar correo de verificación.');
        }
    }

    async refreshToken(
        clientType: ClientType,
        receivedRefreshTokenValue?: string,
        res?: Response
    ): Promise<WebRefreshSuccessResponse | MobileRefreshSuccessResponse> {
        if (!receivedRefreshTokenValue) {
            if (clientType === 'web' && res) this.clearTokenCookies(res);
            throw new UnauthorizedException('No se proporcionó refresh token.');
        }

        try {
            const storedToken = await this.verifyAndRetrieveStoredToken(receivedRefreshTokenValue);

            const { newAccessToken, newRefreshToken } = await this.rotateRefreshToken(storedToken);

            return await this.handleRefreshResponse(clientType, newAccessToken, newRefreshToken, storedToken.user.id, res);

        } catch (error) {
            if (clientType === 'web' && res) {
                this.clearTokenCookies(res);
            }
            throw error;
        }
    }

    private async verifyAndRetrieveStoredToken(tokenValue: string) {
        let decodedPayload: RefreshTokenPayload;
        try {
            decodedPayload = this.jwtService.verify<RefreshTokenPayload>(tokenValue, {
                secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
            });
        } catch (error) {
            this.logger.warn(`Refresh token inválido o expirado (JWT verify failed): ${error.message}`);
            throw new UnauthorizedException('Refresh token inválido o expirado.');
        }

        const hashedToken = this.hashToken(tokenValue);
        const storedToken = await this.prisma.refreshToken.findUnique({
            where: { tokenHash: hashedToken },
            include: {
                user: {
                    select: { 
                         id: true,
                        email: true, 
                        firstName: true,  
                        lastName: true,
                        roleId: true, 
                        isActive: true
                    },
                },
                userSession: true
            },
        });

        if (!storedToken || !storedToken.user || !storedToken.userSession || storedToken.user.id !== decodedPayload.userId || storedToken.userSession.id !== decodedPayload.sessionId) {
            if (storedToken) {
                await this.prisma.refreshToken.delete({ where: { id: storedToken.id } }).catch(e => this.logger.error(`Error al borrar token problemático: ${e.message}`));
            }
            throw new UnauthorizedException('Refresh token no válido (mismatch o no encontrado).');
        }

        if (!storedToken.user.isActive) {
            await this.prisma.refreshToken.delete({ where: { id: storedToken.id } });
            this.logger.warn(`Intento de refresh para usuario inactivo: ${storedToken.user.id}`);
            throw new ForbiddenException('La cuenta de usuario está desactivada.');
        }

        if (new Date(storedToken.expiresAt) < new Date()) {
            await this.prisma.refreshToken.delete({ where: { id: storedToken.id } });
            this.logger.warn(`Refresh token (DB record) expirado para userId: ${decodedPayload.userId}`);
            throw new UnauthorizedException('Refresh token (DB record) expirado.');
        }

        return storedToken;
    }

    private async rotateRefreshToken(storedToken: any) {
        await this.prisma.refreshToken.delete({ where: { id: storedToken.id } });

        const userForTokenGeneration = storedToken.user as User;
        const newAccessToken = await this.generateAccessToken(userForTokenGeneration, storedToken.userSessionId);
        const newRefreshToken = await this.generateRefreshToken(userForTokenGeneration, storedToken.userSessionId);

        const hashedNewRefreshToken = this.hashToken(newRefreshToken);
        const newExpiresAt = new Date();
        newExpiresAt.setDate(newExpiresAt.getDate() + this.JWT_REFRESH_EXPIRATION_DAYS);

        await this.prisma.refreshToken.create({
            data: {
                userId: storedToken.user.id,
                tokenHash: hashedNewRefreshToken,
                expiresAt: newExpiresAt,
                userSessionId: storedToken.userSessionId,
            },
        });

        await this.prisma.userSession.update({
            where: { id: storedToken.userSessionId },
            data: { lastSeenAt: new Date() }
        });

        return { newAccessToken, newRefreshToken };
    }

    private async handleRefreshResponse(clientType: ClientType, accessToken: string, refreshToken: string, userId: number, res?: Response) {
        if (clientType === 'mobile') {
            this.logger.log(`Token refrescado para móvil (usuario ${userId})`);
            return { accessToken, refreshToken };
        }

        if (!res) {
            this.logger.error('Response object (res) no provisto para refresh token web.');
            throw new InternalServerErrorException('Error de configuración del servidor para refresh token web.');
        }
        this.logger.log(`Token refrescado para web (usuario ${userId})`);
        this.setTokenCookies(res, accessToken, refreshToken);
        return { message: 'Token refrescado exitosamente.' };
    }

    async logout(receivedRefreshToken: string | undefined, res: Response): Promise<{ message: string }> {
        if (receivedRefreshToken) {
        const hashedToken = this.hashToken(receivedRefreshToken);
        const tokenRecord = await this.prisma.refreshToken.findUnique({
            where: { tokenHash: hashedToken },
            select: { id: true, userSessionId: true },
        });

        if (tokenRecord) {
            await this.prisma.userSession.delete({ where: { id: tokenRecord.userSessionId } });
            this.logger.log(`Logout: Sesión ${tokenRecord.userSessionId} y su refresh token eliminados.`);
        }
        }
        this.clearTokenCookies(res);
        return { message: 'Logout exitoso.' };
    }

    async validateUserByJwtPayload(payload: AccessTokenPayload): Promise<User | null> {
        const user = await this.prisma.user.findUnique({
            where: { id: payload.userId },
        });

        if (!user?.isActive) {
            return null; 
        }

        const session = await this.prisma.userSession.findUnique({
            where: { id: payload.sessionId }
        });
        if (!session) {
            return null;
        }

        await this.prisma.userSession.update({
            where: { id: payload.sessionId },
            data: { lastSeenAt: new Date() }
        });
        return user;
    }

    async forgotPassword(forgotPasswordDto: ForgotPasswordDto): Promise<{ message: string }> {
        const { email } = forgotPasswordDto;
        const user = await this.usersService.findByEmail(email);

        const genericMessage = 'Si tu email está registrado, recibirás un enlace para restablecer tu contraseña.';

        if (user && user.isActive && user.emailVerified) { 
        const passwordResetToken = uuidv4();
        const hashedPasswordResetToken = this.hashToken(passwordResetToken);
        const passwordResetTokenExpiresInMinutes = 15;
        const passwordResetTokenExpiresAt = new Date(
            Date.now() + passwordResetTokenExpiresInMinutes * 60 * 1000,
        );

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
            passwordResetToken: hashedPasswordResetToken,
            passwordResetTokenExpiresAt,
            },
        });

        this.mailService.sendPasswordResetEmail(user, passwordResetToken, passwordResetTokenExpiresInMinutes)
            .catch(err => this.logger.error('Fallo al enviar email de reseteo de contraseña en segundo plano', err.stack));
        } else if (user && (!user.isActive || !user.emailVerified)) {
        this.logger.warn(`Intento de reseteo para usuario inactivo/no verificado: ${email}`);
        } else {
            this.logger.warn(`Intento de reseteo para email no existente: ${email}`);
        }

        return { message: genericMessage };
    }

    async resetPassword(token: string, resetPasswordDto: ResetPasswordDto): Promise<{ message: string }> {
        if (!token) {
            throw new BadRequestException('Token de reseteo no proporcionado.');
        }
        const { password } = resetPasswordDto;
        const hashedToken = this.hashToken(token);

        const user = await this.prisma.user.findUnique({
            where: { passwordResetToken: hashedToken },
        });

        if (!user) {
            throw new BadRequestException('Token de reseteo inválido o ya utilizado.');
        }

        if (new Date() > new Date(user.passwordResetTokenExpiresAt)) {
            await this.prisma.user.update({
                where: { id: user.id },
                data: { passwordResetToken: null, passwordResetTokenExpiresAt: null },
            });
            throw new BadRequestException('El token de reseteo ha expirado.');
        }

        const newPasswordHash = await this.hashPassword(password);
        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                passwordHash: newPasswordHash,
                passwordResetToken: null, 
                passwordResetTokenExpiresAt: null,
            },
        });

        const sessions = await this.prisma.userSession.findMany({ where: { userId: user.id } });
        if (sessions.length > 0) {
            this.logger.log(`Invalidando ${sessions.length} sesiones para el usuario ${user.id} después del reseteo de contraseña.`);

            await this.prisma.userSession.deleteMany({ where: { userId: user.id } });
        }

        return { message: 'Contraseña restablecida exitosamente.' };
    }
}
