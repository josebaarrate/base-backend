import {
  IsString,
  IsOptional,
  IsUrl,
  MaxLength,
  ValidateIf,
} from 'class-validator';

export class UpdateProfileDto {
  @IsOptional()
  @IsString()
  @MaxLength(100, { message: 'El nombre no puede exceder los 100 caracteres.' })
  firstName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(100, { message: 'Los apellidos no pueden exceder los 100 caracteres.' })
  lastName?: string;

  @IsOptional()
  @ValidateIf(o => o.profileImageUrl !== null && o.profileImageUrl !== undefined && o.profileImageUrl !== '')
  @IsString()
  @IsUrl({}, { message: 'La URL de la imagen de perfil debe ser una URL válida.' })
  profileImageUrl?: string;
}