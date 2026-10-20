import { Role } from '@prisma/client';

export interface CachedUserSession {
  id: string;
  email: string;
  name: string;
  role: Role;
  tokenVersion: number;
  isActive: boolean;
  cachedAt: number;
}

const userSessionCache = new Map<string, CachedUserSession>();
const CACHE_TTL_MS = 2500; // 2.5-second micro-cache for high-throughput burst acceleration

/**
 * Retrieves a user session snapshot from memory if within TTL.
 */
export function getCachedUserSession(userId: string): CachedUserSession | null {
  const cached = userSessionCache.get(userId);
  if (!cached) return null;
  if (Date.now() - cached.cachedAt > CACHE_TTL_MS) {
    userSessionCache.delete(userId);
    return null;
  }
  return cached;
}

/**
 * Stores a user session snapshot into in-memory micro-cache.
 */
export function setCachedUserSession(user: {
  id: string;
  email: string;
  name: string;
  role: Role;
  tokenVersion: number;
  isActive: boolean;
}): void {
  userSessionCache.set(user.id, {
    ...user,
    cachedAt: Date.now()
  });
}

/**
 * Instantly invalidates user session from micro-cache.
 * Defense against Loophole L-01: Instant Revocation & Privilege Demotion.
 */
export function invalidateUserSessionCache(userId?: string): void {
  if (userId) {
    userSessionCache.delete(userId);
  } else {
    userSessionCache.clear();
  }
}
