import { Injectable, Logger } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { LoggedInDto } from './dto/logged-in.dto';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

  private logger = new Logger();

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService
  ) {}

  async validateUser(username: string, password: string): Promise<LoggedInDto> {

    // find user by username
    const user = await this.usersService.findOneByUsername(username);
    if (!user) {
      this.logger.debug(`user not found: username=${username}`, AuthService.name)
      return null
    }

    // found & compare
    if (await bcrypt.compare(password, user.password)) {
      const { password, ...userWithoutPassword} = user;
      return userWithoutPassword;
    } else {
      this.logger.debug(`wrong password: username=${username}`, AuthService.name)
      return null
    }
  }

  login(loggedDto: LoggedInDto): string {
    const payload: LoggedInDto = {...loggedDto, sub: loggedDto.id };
    return this.jwtService.sign(payload);
  }
}
