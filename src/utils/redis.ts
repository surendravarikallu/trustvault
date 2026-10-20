import Redis from 'ioredis';
import { config } from '../config';

const redisUrl = config.redisUrl;

let redisInstance: Redis | null = null;
let isRedisAvailable = false;

// Fallback in-memory map if Redis is temporarily unreachable
const inMemoryFallback = new Map<string, { value: string; expiresAt: number }>();

try {
  redisInstance = new Redis(redisUrl, {
    maxRetriesPerRequest: 1,
    retryStrategy: (times) => {
      // Exponential backoff capped at 2 seconds
      return Math.min(times * 100, 2000);
    },
    lazyConnect: true,
    enableReadyCheck: true,
  });

  redisInstance.on('connect', () => {
    isRedisAvailable = true;
  });

  redisInstance.on('ready', () => {
    isRedisAvailable = true;
  });

  redisInstance.on('error', (_err) => {
    isRedisAvailable = false;
  });

  redisInstance.on('close', () => {
    isRedisAvailable = false;
  });

  // Connect asynchronously without blocking startup
  redisInstance.connect().catch(() => {
    isRedisAvailable = false;
  });
} catch {
  isRedisAvailable = false;
  redisInstance = null;
}

export function isRedisConnected(): boolean {
  return isRedisAvailable && redisInstance?.status === 'ready';
}

export async function redisGet(key: string): Promise<string | null> {
  if (isRedisConnected() && redisInstance) {
    try {
      return await redisInstance.get(key);
    } catch {
      // Graceful fallback to in-memory on unexpected failure
    }
  }

  const cached = inMemoryFallback.get(key);
  if (!cached) return null;
  if (Date.now() > cached.expiresAt) {
    inMemoryFallback.delete(key);
    return null;
  }
  return cached.value;
}

export async function redisSet(key: string, value: string, ttlSeconds = 60): Promise<void> {
  if (isRedisConnected() && redisInstance) {
    try {
      if (ttlSeconds > 0) {
        await redisInstance.set(key, value, 'EX', ttlSeconds);
      } else {
        await redisInstance.set(key, value);
      }
      return;
    } catch {
      // Graceful fallback to in-memory
    }
  }

  inMemoryFallback.set(key, {
    value,
    expiresAt: ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : Infinity,
  });
}

export async function redisDel(key: string | string[]): Promise<void> {
  const keys = Array.isArray(key) ? key : [key];
  if (keys.length === 0) return;

  for (const k of keys) {
    inMemoryFallback.delete(k);
  }

  if (isRedisConnected() && redisInstance) {
    try {
      await redisInstance.del(...keys);
    } catch {
      // Silent catch
    }
  }
}

export async function redisIncr(key: string, ttlSeconds?: number): Promise<number> {
  if (isRedisConnected() && redisInstance) {
    try {
      const val = await redisInstance.incr(key);
      if (ttlSeconds && val === 1) {
        await redisInstance.expire(key, ttlSeconds);
      }
      return val;
    } catch {
      // Fallback
    }
  }

  const existing = await redisGet(key);
  const nextVal = (existing ? parseInt(existing, 10) : 0) + 1;
  await redisSet(key, String(nextVal), ttlSeconds || 3600);
  return nextVal;
}

export async function closeRedis(): Promise<void> {
  if (redisInstance) {
    try {
      await redisInstance.quit();
    } catch {
      redisInstance.disconnect();
    }
  }
}

export { redisInstance };
