import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { Prisma, User } from '@prisma/client';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable({})
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}

  async signUp({ email, password }: AuthDto) {
    const hash = await argon.hash(password);

    try {
      const user: User = await this.prisma.user.create({
        data: {
          email,
          hash,
        },
      });

      return this.getSignToken(user.id, user.email);
    } catch (error) {
      if (error instanceof PrismaClientKnownRequestError) {
        const takenCode = 'P2002';

        if (error.code === takenCode) {
          throw new ForbiddenException('Credentials already taken');
        }
      }

      throw error;
    }
  }

  async signIn({ email, password }: AuthDto) {
    const user: User = await this.prisma.user.findUnique({
      where: {
        email,
      },
    });

    if (!user) {
      throw new ForbiddenException('Some value is incorrect');
    }

    const passwordMatch: boolean = await argon.verify(user.hash, password);

    if (!passwordMatch) {
      throw new ForbiddenException('Some value is incorrect');
    }

    return this.getSignToken(user.id, user.email);
  }

  async getSignToken(
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };

    const secret = this.config.get('JWT_SECRET');

    const access_token = await this.jwt.signAsync(payload, {
      expiresIn: '15m',
      secret,
    });

    return {
      access_token,
    };
  }
}
