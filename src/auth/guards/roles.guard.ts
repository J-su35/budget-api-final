import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { Observable } from 'rxjs';
import { LoggedInDto } from '../dto/logged-in.dto';
import { Role } from 'src/users/entities/user.entity';
import { Roles } from '../decorators/roles.decorator';
import { Reflector } from '@nestjs/core';


@Injectable()
export class RolesGuard implements CanActivate {

  constructor(private reflector: Reflector) {}
  
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {

    // const request = context.switchToHttp().getRequest();
    // const user: LoggedInDto = request.user;

    // return user.role === Role.ADMIN;

    const roles = this.reflector.get(Roles, context.getHandler())

    if (!roles) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const user: LoggedInDto = request.user;

    return roles.includes(user.role);
  }
}