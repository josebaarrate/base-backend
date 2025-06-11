import { IsString, IsOptional, IsJWT } from 'class-validator';

export class MobileRefreshTokenDto {
  @IsOptional()
  @IsString()
  @IsJWT() 
  refreshToken?: string;
}