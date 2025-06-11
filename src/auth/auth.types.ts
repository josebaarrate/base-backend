import { User } from '@prisma/client'; 

export interface WebLoginSuccessPayload {
  user: Omit<User, 'passwordHash' | 'emailVerificationToken' | 'emailVerificationTokenExpiresAt' | 'passwordResetToken' | 'passwordResetTokenExpiresAt'>;
  profileCompletion: number;
}

export interface UserProfile extends Omit<User, 'passwordHash' | 'emailVerificationToken' | 'emailVerificationTokenExpiresAt' | 'passwordResetToken' | 'passwordResetTokenExpiresAt'> {
  profileCompletion: number;
}

export interface WebLoginSuccessResponse {
  statusCode: number;
  message: string;
  data: {
    user: UserProfile;
  };
}

export interface MobileLoginSuccessResponse {
  accessToken: string;
  refreshToken: string;
  user: UserProfile;
}

export interface MobileRefreshSuccessResponse {
  accessToken: string;
  refreshToken: string;
}

export interface WebRefreshSuccessResponse {
  message: string;
}