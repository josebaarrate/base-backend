import { Controller, UseGuards, Body, HttpStatus, Patch, HttpCode } from '@nestjs/common'; // Añadir
import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
import { AuthenticatedUser, GetCurrentUser } from 'src/auth/decorators/get-current-user.decorator';
import { UsersService } from './users.service';
import { UpdateProfileDto } from './dtos/update-profile.dto';

@Controller('users') 
@UseGuards(JwtAuthGuard)
export class UsersController {
  constructor(
    private readonly usersService: UsersService
  ) {}

  @Patch('me/profile') 
  @HttpCode(HttpStatus.OK) 
  async updateMyProfile(
    @GetCurrentUser() userFromToken: AuthenticatedUser, 
    @Body() updateProfileDto: UpdateProfileDto, 
  ) {
    const updatedUser = await this.usersService.updateUserProfile(userFromToken.id, updateProfileDto);
    return {
      statusCode: HttpStatus.OK,
      message: 'Perfil actualizado exitosamente.',
      data: updatedUser, 
    };
  }
}