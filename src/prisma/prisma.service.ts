import { Injectable } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
const databaseUrl = process.env.DATABASE_URL;

@Injectable()
export class PrismaService extends PrismaClient {
  constructor() {
    super({
      datasources: {
        db: {
          url: databaseUrl,
        },
      },
    });
  }
}
