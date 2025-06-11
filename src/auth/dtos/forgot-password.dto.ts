import { IsEmail, IsNotEmpty } from 'class-validator';

export class ForgotPasswordDto {
    @IsNotEmpty({ message: 'El email no puede estar vacío.' })
    @IsEmail({}, { message: 'Debe ser un email válido.' })
    email: string;
}