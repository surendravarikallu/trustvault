import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { resolveDatabaseUrl } from '../src/prisma';
import { assertNonPrivilegedRuntimeRole } from '../src/server';
import { prisma } from '../src/prisma';

describe('Runtime Database Role Separation & Startup Assertions', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('ROLE-01: Production runtime strictly refuses to boot if APP_DATABASE_URL is missing (no fallback)', () => {
    process.env.NODE_ENV = 'production';
    delete process.env.APP_DATABASE_URL;

    expect(() => {
      resolveDatabaseUrl();
    }).toThrow(/CRITICAL SECURITY ERROR: Missing required APP_DATABASE_URL/i);
  });

  it('ROLE-02: Production runtime resolves APP_DATABASE_URL when properly configured', () => {
    process.env.NODE_ENV = 'production';
    process.env.APP_DATABASE_URL = 'postgresql://trustvault_app:app_secure_password@localhost:5432/trustvault';

    const resolved = resolveDatabaseUrl();
    expect(resolved).toBe('postgresql://trustvault_app:app_secure_password@localhost:5432/trustvault');
  });

  it('ROLE-03: assertNonPrivilegedRuntimeRole executes and verifies the role is non-privileged', async () => {
    // Current test connection runs as non-privileged role trustvault_app
    const query: any = await prisma.$queryRawUnsafe('SELECT current_user');
    const currentUser = query[0]?.current_user;

    if (currentUser === 'trustvault_app') {
      await expect(assertNonPrivilegedRuntimeRole()).resolves.toBeUndefined();
    } else {
      // If run as postgres superuser, assertion MUST reject and throw
      await expect(assertNonPrivilegedRuntimeRole()).rejects.toThrow(/CRITICAL SECURITY VIOLATION/i);
    }
  });
});
