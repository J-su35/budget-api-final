import { Injectable, Logger, NestMiddleware } from '@nestjs/common';

@Injectable()
export class LoginLoggerMiddleware implements NestMiddleware {

  private logger = new Logger();

  use(req: any, res: any, next: () => void) {

    const { ip, headers, body } = req;
    const userAgent = headers['user-agent'] || '';
    const username = body?.username

    this.logger.log(`IP:${ip}, Agent:${userAgent}, Username: ${username}`, LoginLoggerMiddleware.name)

    res.on('finish', () => {
      const statusCode = res.statusCode;
      if (statusCode === 401 || statusCode === 404 || statusCode === 405) {
        this.logger.warn(`IP:${ip}, Agent:${userAgent}, Username: ${username} - ${statusCode}`, LoginLoggerMiddleware.name)
      }
    })
    next();
  }
}
