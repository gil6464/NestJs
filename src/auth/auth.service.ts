import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { Prisma, User } from '@prisma/client';

@Injectable({})
export class AuthService {
  constructor(private prisma: PrismaService) {}

  async signUp({ email, password }: AuthDto) {
    const hash = await argon.hash(password);

    try {
      const user: User = await this.prisma.user.create({
        data: {
          email,
          hash,
        },
      });

      delete user.hash;
      return user;
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

    delete user.hash;
    return { message: 'Im sign in' };
  }
}
