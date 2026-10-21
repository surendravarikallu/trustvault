// eslint-disable-next-line no-restricted-imports
import { PrismaClient } from '@prisma/client';
import { config } from './config';

declare global {
  var __trustvault_prisma__: PrismaClient | undefined;
}

/**
 * Resolves the appropriate database URL based on runtime environment.
 * In production, strictly requires APP_DATABASE_URL (trustvault_app role)
 * and refuses to fallback to privileged DATABASE_URL (postgres superuser).
 */
export function resolveDatabaseUrl(): string {
  if (process.env.NODE_ENV === 'test') {
    const testUrl = process.env.TEST_DATABASE_URL || config.testDatabaseUrl;
    if (!testUrl) {
      throw new Error('Missing TEST_DATABASE_URL for test environment.');
    }
    return testUrl;
  }

  if (process.env.NODE_ENV === 'production') {
    const appDbUrl = process.env.APP_DATABASE_URL;
    if (!appDbUrl) {
      throw new Error(
        'CRITICAL SECURITY ERROR: Missing required APP_DATABASE_URL in production environment. Refusing to fallback to DATABASE_URL.'
      );
    }
    return appDbUrl;
  }

  // Development
  const devUrl = process.env.APP_DATABASE_URL || config.appDatabaseUrl || process.env.DATABASE_URL || config.databaseUrl;
  if (!devUrl) {
    throw new Error('Missing database connection URL. Please set APP_DATABASE_URL or DATABASE_URL.');
  }
  return devUrl;
}

export const prisma =
  global.__trustvault_prisma__ ||
  new PrismaClient({
    datasources: {
      db: {
        url: resolveDatabaseUrl()
      }
    },
    log: process.env.NODE_ENV === 'development' ? ['warn', 'error'] : ['error']
  });

if (process.env.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'test') {
  global.__trustvault_prisma__ = prisma;
}

export default prisma;
