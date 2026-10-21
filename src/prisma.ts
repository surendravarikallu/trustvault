import { PrismaClient } from '@prisma/client';

declare global {
  // eslint-disable-next-line no-var
  var __trustvault_prisma__: PrismaClient | undefined;
}

/**
 * Centralized PrismaClient Singleton.
 * 
 * Performance & Database Optimization:
 * Eliminates connection pool multiplication (previously 6 separate DAL instances
 * created up to 150 connection slots, causing pool exhaustion under concurrency).
 * Consolidates all database operations into a single coordinated connection pool.
 */
import { config } from './config';

export const prisma =
  global.__trustvault_prisma__ ||
  new PrismaClient({
    datasources: {
      db: {
        url: process.env.NODE_ENV === 'test'
          ? (process.env.TEST_DATABASE_URL || config.testDatabaseUrl)
          : (process.env.DATABASE_URL || config.databaseUrl)
      }
    },
    log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error']
  });

if (process.env.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'test') {
  global.__trustvault_prisma__ = prisma;
}

export default prisma;
