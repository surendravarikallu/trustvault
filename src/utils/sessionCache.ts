import { Role } from '@prisma/client';
import { redisGet, redisSet, redisDel, isRedisConnected } from './redis';

export interface CachedUserSession {
  id: string;
  email: string;
  name: string;
  role: Role;
  tokenVersion: number;
  isActive: boolean;
  cachedAt: number;
}

const localUserSessionCache = new Map<string, CachedUserSession>();
const CACHE_TTL_MS = 2500; // 2.5-second micro-cache for high-throughput burst acceleration

/**
 * Retrieves a user session snapshot from memory or Redis.
 */
export async function getCachedUserSessionAsync(userId: string): Promise<CachedUserSession | null> {
  // 1. Check ultra-fast local memory first (< 0.1ms)
  const local = localUserSessionCache.get(userId);
  if (local) {
    if (Date.now() - local.cachedAt <= CACHE_TTL_MS) {
      return local;
    }
    localUserSessionCache.delete(userId);
  }

  // 2. Check distributed Redis cache if connected
  if (isRedisConnected()) {
    try {
      const raw = await redisGet(`session:${userId}`);
      if (raw) {
        const session: CachedUserSession = JSON.parse(raw);
        // Hydrate local cache for subsequent instant hits
        localUserSessionCache.set(userId, session);
        return session;
      }
    } catch {
      // Ignore Redis read errors
    }
  }

  return null;
}

/**
 * Synchronous local retrieval for zero-async overhead in hot paths.
 */
export function getCachedUserSession(userId: string): CachedUserSession | null {
  const cached = localUserSessionCache.get(userId);
  if (!cached) return null;
  if (Date.now() - cached.cachedAt > CACHE_TTL_MS) {
    localUserSessionCache.delete(userId);
    return null;
  }
  return cached;
}

/**
 * Stores a user session snapshot into in-memory micro-cache and distributed Redis.
 */
export function setCachedUserSession(user: {
  id: string;
  email: string;
  name: string;
  role: Role;
  tokenVersion: number;
  isActive: boolean;
}): void {
  const session: CachedUserSession = {
    ...user,
    cachedAt: Date.now()
  };

  localUserSessionCache.set(user.id, session);

  // Asynchronously replicate to Redis for cross-worker cluster sync (TTL 3 seconds)
  if (isRedisConnected()) {
    redisSet(`session:${user.id}`, JSON.stringify(session), 3).catch(() => {});
  }
}

/**
 * Instantly invalidates user session from micro-cache and distributed Redis cluster.
 * Defense against Loophole L-01: Instant Revocation & Privilege Demotion.
 */
export function invalidateUserSessionCache(userId?: string): void {
  if (userId) {
    localUserSessionCache.delete(userId);
    if (isRedisConnected()) {
      redisDel(`session:${userId}`).catch(() => {});
    }
  } else {
    localUserSessionCache.clear();
  }
}
