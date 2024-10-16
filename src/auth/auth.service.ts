import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { LoggedInDto } from './dto/logged-in.dto';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService
  ) {}

  async validateUser(username: string, password: string): Promise<LoggedInDto> {

    // find user by username
    const user = await this.usersService.findOneByUsername(username);
    if (!user) {
      console.log(`user not found: username=${username}`)
      return null
    }

    // found & compare
    if (await bcrypt.compare(password, user.password)) {
      const { password, ...userWithoutPassword} = user;
      return userWithoutPassword;
    } else {
      console.log(`wrong password: username=${username}`)
      return null
    }
  }

  login(loggedDto: LoggedInDto): string {
    const payload: LoggedInDto = {...loggedDto, sub: loggedDto.id };
    return this.jwtService.sign(payload);
  }
}
