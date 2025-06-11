import { SetMetadata } from '@nestjs/common';

export enum RoleEnum {
  USER = 1,
  ADMIN = 2, 
  MODERATOR = 3,
}

export const ROLES_KEY = 'roles';
export const Roles = (...roles: RoleEnum[]) => SetMetadata(ROLES_KEY, roles);