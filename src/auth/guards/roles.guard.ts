import { Injectable, CanActivate, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY, RoleEnum } from '../decorators/roles.decorator';
import { AuthenticatedUser } from '../decorators/get-current-user.decorator';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<RoleEnum[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) {
      return true;
    }
    const { user } = context.switchToHttp().getRequest<{ user: AuthenticatedUser }>();

    if (!user || !user.roleId) return false;

    return requiredRoles.some((role) => user.roleId === role); 
  }
}