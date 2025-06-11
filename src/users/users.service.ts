import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { Prisma, User } from '@prisma/client';
import { UpdateProfileDto } from './dtos/update-profile.dto';
import { UserProfile } from 'src/auth/auth.types';

@Injectable()
export class UsersService {
  constructor(private readonly prisma: PrismaService) {}

  private sanitizeUserForOutput(user: User): Omit<User, 'passwordHash' | 'emailVerificationToken' | 'emailVerificationTokenExpiresAt' | 'passwordResetToken' | 'passwordResetTokenExpiresAt'> {
    const { passwordHash, emailVerificationToken, emailVerificationTokenExpiresAt, passwordResetToken, passwordResetTokenExpiresAt, ...result } = user;
    return result;
  }

  async updateUserProfile(
    userId: number,
    updateProfileDto: UpdateProfileDto,
  ): Promise<Omit<User, 'passwordHash' | 'emailVerificationToken' | 'emailVerificationTokenExpiresAt' | 'passwordResetToken' | 'passwordResetTokenExpiresAt'>> {
    
    const {
      firstName, lastName, profileImageUrl,
    } = updateProfileDto;

    const dataToUpdate: Prisma.UserUpdateInput = {};

    if (firstName !== undefined) dataToUpdate.firstName = firstName;
    if (lastName !== undefined) dataToUpdate.lastName = lastName;
    if (profileImageUrl !== undefined) dataToUpdate.profileImageUrl = profileImageUrl;

    if (Object.keys(dataToUpdate).length === 0) {
      const currentUser = await this.prisma.user.findUnique({ where: { id: userId } });
      if (!currentUser) throw new NotFoundException('Usuario no encontrado.');
      return this.sanitizeUserForOutput(currentUser);
    }

    try {
      const updatedUser = await this.prisma.user.update({
        where: { id: userId },
        data: dataToUpdate,
      });
      return this.sanitizeUserForOutput(updatedUser);
    } catch (error: any) {
      if (error.code === 'P2025') { 
        throw new BadRequestException('El ID de industria, provincia o ciudad proporcionado no es válido o no existe.');
      }
      throw new InternalServerErrorException('Error al actualizar el perfil del usuario.');
    }
  }

  async findByEmail(email: string): Promise<User | null> {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }

  async findById(id: number): Promise<Omit<User, 'passwordHash'> | null> {
    const user = await this.prisma.user.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        profileImageUrl: true,
        roleId: true,
        emailVerificationToken: true,
        emailVerificationTokenExpiresAt: true,
        emailVerified: true,
        passwordResetToken: true,
        passwordResetTokenExpiresAt: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      }
    });
    return user;
  }

  public calculateProfileCompletion(user: User): number {
    let completedFields = 0;
    const totalManagedFields = 12;

    if (user.firstName && user.firstName.trim() !== '') completedFields++;
    if (user.lastName && user.lastName.trim() !== '') completedFields++;

    if (user.profileImageUrl && user.profileImageUrl.trim() !== '') completedFields++;
    
    let percentage = (completedFields / totalManagedFields) * 100;
    return Math.min(Math.round(percentage), 100); 
  }

  async findByIdWithProfileCompletion(id: number): Promise<UserProfile | null> {
    const user = await this.prisma.user.findUnique({
      where: { id }
    });

    if (!user) {
      return null;
    }

    const profileCompletion = this.calculateProfileCompletion(user);
    const { passwordHash, emailVerificationToken, emailVerificationTokenExpiresAt, passwordResetToken, passwordResetTokenExpiresAt, ...sanitizedUser } = user;

    return {
      ...sanitizedUser,
      profileCompletion,
    };
  }
}