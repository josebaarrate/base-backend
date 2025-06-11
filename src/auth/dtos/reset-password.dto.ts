import { IsNotEmpty, MinLength } from 'class-validator';

export class ResetPasswordDto {
    @IsNotEmpty({ message: 'La contraseña no puede estar vacía.' })
    @MinLength(8, { message: 'La contraseña debe tener al menos 8 caracteres.' })
    password: string;
}