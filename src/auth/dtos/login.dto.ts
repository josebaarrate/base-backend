import { IsEmail, IsNotEmpty } from 'class-validator';

export class LoginDto {
    @IsNotEmpty({ message: 'El email no puede estar vacío.' })
    @IsEmail({}, { message: 'El email debe ser un correo válido.' })
    email: string;

    @IsNotEmpty({ message: 'La contraseña no puede estar vacía.' })
    password: string;
}