import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { Response } from 'express';
import { compare, hash } from 'bcryptjs';
import { UsersService } from '../users/users.service';
import { User } from '../users/schema/users.schema';
import { TokenPayload } from './token-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly usersService: UsersService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async login(user: User, response: Response) {
    // console.log('[auth.service.ts] login - user: ', user);
    const expiresAccessToken = new Date();
    expiresAccessToken.setMilliseconds(
      expiresAccessToken.getTime() +
        parseInt(
          this.configService.getOrThrow<string>(
            'JWT_ACCESS_TOKEN_EXPIRATION_MS',
          ),
        ),
    );
    const expiresRefreshToken = new Date();
    expiresRefreshToken.setMilliseconds(
      expiresRefreshToken.getTime() +
        parseInt(
          this.configService.getOrThrow<string>(
            'JWT_REFRESH_TOKEN_EXPIRATION_MS',
          ),
        ),
    );
    const tokenPayload: TokenPayload = {
      userId: user._id.toHexString(),
    };
    const accessToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_ACCESS_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow('JWT_ACCESS_TOKEN_EXPIRATION_MS')}ms`,
    });

    const refreshToken = this.jwtService.sign(tokenPayload, {
      secret: this.configService.getOrThrow('JWT_REFRESH_TOKEN_SECRET'),
      expiresIn: `${this.configService.getOrThrow('JWT_REFRESH_TOKEN_EXPIRATION_MS')}ms`,
    });

    await this.usersService.updateUser(
      { _id: user._id },
      { $set: { refreshToken: await hash(refreshToken, 10) }},
    );

    response.cookie('Authentication', accessToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresAccessToken,
    });

    response.cookie('Refresh', refreshToken, {
      httpOnly: true,
      secure: this.configService.get('NODE_ENV') === 'production',
      expires: expiresRefreshToken,
    });
  }

  async verifyUser(email: string, password: string) {
    try {
      const user = await this.usersService.getUser({ email });
      // console.log('verifyUser user: ', user);
      const authenticated = await compare(password, user.password);
      // console.log('authenticated: ', authenticated);
      if (!authenticated) {
        throw new UnauthorizedException('Invalid credentials!');
      }
      return user;
    } catch (err) {
      console.error('Error while verifying user credentials: ', err);
      throw new UnauthorizedException('Invalid credentials!');
    }
  }

  async verifyUserRefreshToken(refreshToken: string, userId: string) {
    try {
      const user = await this.usersService.getUser({ _id: userId });
      if (!user.refreshToken) throw new UnauthorizedException();
      const authenticated = await compare(refreshToken, user.refreshToken);
      if (!authenticated) throw new UnauthorizedException();
      return user;
    } catch (err) {
      console.error('[auth.service.ts] verifyUserRefreshToken - error: ', err);
      throw new UnauthorizedException('Refresh token is not valid');
    }
  }
}
