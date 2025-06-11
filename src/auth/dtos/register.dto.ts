import { IsEmail, IsNotEmpty, MinLength, IsString, IsOptional, IsInt, IsUrl } from 'class-validator';

export class RegisterDto { 
  @IsNotEmpty()
  @IsEmail()
  email!: string;

  @IsNotEmpty()
  @MinLength(8)
  password!: string;

  @IsOptional()
  @IsString()
  firstName?: string;

  @IsOptional()
  @IsString()
  lastName?: string;

  @IsOptional()
  @IsString()
  @IsUrl() 
  profileImageUrl?: string;

  @IsOptional()
  @IsInt()
  roleId?: number;
}