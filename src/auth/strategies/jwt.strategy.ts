import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';
import { User } from '@prisma/client';
import { AccessTokenPayload } from '../interfaces/AccessTokenPayload.inteface';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    private readonly configService: ConfigService,
    private readonly authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        (request) => {
          return request?.cookies?.['accessToken'] ?? null;
        },
        ExtractJwt.fromAuthHeaderAsBearerToken(),
      ]),
      ignoreExpiration: false,
      secretOrKey: configService.get<string>('JWT_ACCESS_SECRET'),
    });
  }

  async validate(payload: AccessTokenPayload): Promise<Omit<User, 'passwordHash'> & { sessionId: number, roleId?: number }> {
    const user = await this.authService.validateUserByJwtPayload(payload);
    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado, inactivo o sesión inválida.');
    }
    const { passwordHash, ...userWithoutPassword } = user;
    return { ...userWithoutPassword, sessionId: payload.sessionId, roleId: payload.roleId };
  }
}