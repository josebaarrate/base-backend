import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { JsonWebTokenError, TokenExpiredError } from 'jsonwebtoken';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') { 
    canActivate(context: ExecutionContext) {
        return super.canActivate(context);
    }

    handleRequest(err, user, info: Error, context: ExecutionContext, status?: any) {
        if (info instanceof TokenExpiredError) {
            throw new UnauthorizedException({
                statusCode: 401,
                message: 'Token de acceso expirado.',
                error: 'Unauthorized',
                reason: 'TOKEN_EXPIRED'
            });
        }
        if (info instanceof JsonWebTokenError) {
            throw new UnauthorizedException({
                statusCode: 401,
                message: 'Token de acceso inválido.',
                error: 'Unauthorized',
                reason: 'TOKEN_INVALID'
            });
        }
        if (err || !user) {
            const message = info?.message || 'No autorizado';
            throw err ?? new UnauthorizedException(message);
        }
        return user;
    }
}