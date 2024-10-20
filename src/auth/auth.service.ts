import { Injectable, Logger } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { LoggedInDto } from './dto/logged-in.dto';
import { UsersService } from 'src/users/users.service';
import { JwtService } from '@nestjs/jwt';
import { v7 as uuidv7 } from 'uuid';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {

  private logger = new Logger();
  

  constructor(
    private usersService: UsersService,
    private jwtService: JwtService,
    private configService: ConfigService //new key cloak
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


  //new
  getOauth2RedirectUrl(): string {
    const auth_url = this.configService.get('OAUTH2_AUTH_URL')
    const client_id = this.configService.get('OAUTH2_CLIENT_ID');
    const redirect_uri = this.configService.get('OAUTH2_CALLBACK_URL');
    const scope = encodeURIComponent(this.configService.get('OAUTH2_SCOPE'));
    const response_type = this.configService.get('OAUTH2_RESPONSE_TYPE');
    const state = uuidv7();
    return `${auth_url}?client_id=${client_id}&redirect_uri=${redirect_uri}&scope=${scope}&response_type=${response_type}&state=${state}`
  }
  //new
  async validateUserByAccessToken(accessToken: string): Promise<LoggedInDto> {

    const userInfo: { preferred_username: string } = await this.jwtService.decode(accessToken);

    const user = await this.usersService.findOneByUsername(userInfo.preferred_username);
    if (!user) {
      this.logger.debug(`user not found: username=${userInfo.preferred_username}`, AuthService.name)
      return null
    }

    const { password, ...userWithoutPassword} = user;
    
    return userWithoutPassword;
  }
}
