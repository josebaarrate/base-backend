import { Controller, Post, Body, Res, Req, Ip, Headers, UseGuards, Get, HttpStatus, HttpCode, Patch, BadRequestException, Query, ValidationPipe, UnauthorizedException, NotFoundException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { RegisterDto } from './dtos/register.dto';
import { LoginDto } from './dtos/login.dto';
import { Response, Request } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthenticatedUser, GetCurrentUser } from './decorators/get-current-user.decorator';
import { Throttle } from '@nestjs/throttler';
import { ForgotPasswordDto } from './dtos/forgot-password.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { ClientType, GetClientType } from 'src/common/decorators/client-type.decorator';
import { MobileRefreshTokenDto } from './dtos/refresh-token.dto';
import { UsersService } from 'src/users/users.service';

@Controller('auth')
export class AuthController {
    constructor(
        private readonly authService: AuthService,
        private readonly usersService: UsersService
    ) {}

    @Post('register')
    async register(@Body() registerDto: RegisterDto) {
        const user = await this.authService.register(registerDto);
        return {
        statusCode: HttpStatus.CREATED,
        message: 'Usuario registrado exitosamente.',
        data: user,
        };
    }

    @Post('login')
    @HttpCode(HttpStatus.OK) 
    async login(
        @Body() loginUserDto: LoginDto,
        @Ip() ipAddress: string,
        @Headers('user-agent') userAgent: string,
        @GetClientType() clientType: ClientType,
        @Res({ passthrough: true }) res: Response, 
    ) {
        if (clientType === 'mobile') {
            return this.authService.login(loginUserDto, ipAddress, userAgent, clientType);
        } else {
            return this.authService.login(loginUserDto, ipAddress, userAgent, clientType, res);
        }
    }

    @Post('refresh-token')
    @HttpCode(HttpStatus.OK)
    async refreshTokenEndpoint(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
        @GetClientType() clientType: ClientType,
        @Body(new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: false, skipMissingProperties: true }))
        body: MobileRefreshTokenDto,
    ) {
        let receivedRefreshTokenValue: string | undefined;

        if (clientType === 'mobile') {
            if (!body || typeof body.refreshToken !== 'string' || body.refreshToken.trim() === '') {
                throw new BadRequestException('El campo refreshToken (string no vacío) es requerido en el body para clientes móviles.');
            }
            receivedRefreshTokenValue = body.refreshToken;
        } else {
            if (Object.keys(body).length > 0 && body.refreshToken !== undefined) {
                throw new BadRequestException('Los clientes web no deben enviar un body a este endpoint.');
            }
            receivedRefreshTokenValue = req.cookies['refreshToken'];
        }

        if (!receivedRefreshTokenValue) {
            throw new UnauthorizedException('No se proporcionó refresh token.');
        }

        if (clientType === 'mobile') {
            return this.authService.refreshToken(clientType, receivedRefreshTokenValue);
        } else {
            return this.authService.refreshToken(clientType, receivedRefreshTokenValue, res);
        }
    }

    @UseGuards(JwtAuthGuard)
    @Post('logout')
    @HttpCode(HttpStatus.OK)
    async logout(
        @Req() req: Request,
        @Res({ passthrough: true }) res: Response,
    ) {
        const receivedRefreshToken = req.cookies['refreshToken'];
        const result = await this.authService.logout(receivedRefreshToken, res);
        return {
        statusCode: HttpStatus.OK,
        message: result.message,
        };
    }

    @UseGuards(JwtAuthGuard)
    @Get('me')
    async getProfile(@GetCurrentUser() userFromToken: AuthenticatedUser) {
        const userProfile = await this.usersService.findByIdWithProfileCompletion(userFromToken.id);

        if (!userProfile) {
          throw new NotFoundException('Usuario no encontrado.');
        }
        return {
            statusCode: HttpStatus.OK,
            data: userProfile
        };
    }

    @UseGuards(JwtAuthGuard)
    @Patch('send-verify-email')
    @HttpCode(HttpStatus.OK)
    async sendVerifyEmail(@GetCurrentUser() userFromToken: AuthenticatedUser) {
        if (!userFromToken) {
            throw new BadRequestException('Token de verificación es requerido.');
        }
        const result = await this.authService.sendVerifyEmail(userFromToken.id);
        return {
            statusCode: HttpStatus.OK,
            message: result.message,
        };
    }

    @Patch('verify-email') 
    @HttpCode(HttpStatus.OK)
    @Throttle({ default: { limit: 5, ttl: 60000 * 10 }})
    async verifyEmail(@Query('token') token: string) {
        if (!token) {
        throw new BadRequestException('Token de verificación es requerido.');
        }
        const result = await this.authService.verifyEmail(token);
        return {
            statusCode: HttpStatus.OK,
            message: result.message,
        };
    }

    @Post('forgot-password')
    @HttpCode(HttpStatus.OK)
    @Throttle({ default: { limit: 3, ttl: 60000 * 10 }})
    async forgotPassword(@Body() forgotPasswordDto: ForgotPasswordDto) {
        const result = await this.authService.forgotPassword(forgotPasswordDto);
        return {
        statusCode: HttpStatus.OK,
        message: result.message, 
        };
    }

    @Patch('reset-password') 
    @HttpCode(HttpStatus.OK)
    @Throttle({ default: { limit: 3, ttl: 60000 * 10 }})
    async resetPassword(
        @Query('token') token: string,
        @Body() resetPasswordDto: ResetPasswordDto,
    ) {
        if (!token) {
        throw new BadRequestException('Token de reseteo es requerido.');
        }
        const result = await this.authService.resetPassword(token, resetPasswordDto);
        return {
        statusCode: HttpStatus.OK,
        message: result.message,
        };
    }
}