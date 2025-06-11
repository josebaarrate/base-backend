import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { User } from '@prisma/client';

export type AuthenticatedUser = Omit<User, 'passwordHash'> & { sessionId: number, roleId?: number };

export const GetCurrentUser = createParamDecorator(
  (data: keyof AuthenticatedUser | undefined, context: ExecutionContext): AuthenticatedUser | AuthenticatedUser[keyof AuthenticatedUser] | null => {
    const request = context.switchToHttp().getRequest();
    if (!request.user) {
      return null;
    }
    if (data) {
      return request.user[data];
    }
    return request.user as AuthenticatedUser;
  },
);