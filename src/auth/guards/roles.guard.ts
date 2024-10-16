import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';
import { LoggedInDto } from '../dto/logged-in.dto';
import { Role } from 'src/users/entities/user.entity';


@Injectable()
export class RolesGuard implements CanActivate {
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {

    const request = context.switchToHttp().getRequest();
    const user: LoggedInDto = request.user;

    return user.role === Role.ADMIN;
  }
}