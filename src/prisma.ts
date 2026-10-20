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
export const prisma =
  global.__trustvault_prisma__ ||
  new PrismaClient({
    log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error']
  });

if (process.env.NODE_ENV !== 'production') {
  global.__trustvault_prisma__ = prisma;
}

export default prisma;
