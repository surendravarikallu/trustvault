import { prisma } from '../prisma';
import { redisGet, redisSet, isRedisConnected } from '../utils/redis';

// High-speed in-memory micro-cache of revoked session IDs (<0.01ms lookup)
const localRevokedSessions = new Set<string>();

/**
 * Creates a persistent session in PostgreSQL and returns the session ID (jti).
 */
export async function createSession(userId: string, expiresInHours = 8): Promise<string> {
  const expiresAt = new Date(Date.now() + expiresInHours * 3600 * 1000);
  const session = await prisma.session.create({
    data: {
      userId,
      expiresAt
    }
  });
  return session.id;
}

/**
 * Validates whether a session ID is active, non-expired, and has not been revoked.
 */
export async function isSessionValid(sessionId: string): Promise<boolean> {
  if (!sessionId) return false;

  // 1. Check local in-memory revoked set
  if (localRevokedSessions.has(sessionId)) {
    return false;
  }

  // 2. Check distributed Redis blacklist
  if (isRedisConnected()) {
    try {
      const revoked = await redisGet(`revoked_session:${sessionId}`);
      if (revoked) {
        localRevokedSessions.add(sessionId);
        return false;
      }
    } catch {
      // Non-blocking fallback to DB
    }
  }

  // 3. Check persistent database state
  try {
    const session = await prisma.session.findUnique({
      where: { id: sessionId },
      select: { revokedAt: true, expiresAt: true }
    });

    if (!session) {
      return false;
    }

    if (session.revokedAt !== null || session.expiresAt <= new Date()) {
      localRevokedSessions.add(sessionId);
      return false;
    }

    return true;
  } catch (error) {
    console.error('Session validation database error:', error);
    // Zero-trust: fail closed on database errors
    return false;
  }
}

/**
 * Instantly revokes a single session.
 * Used on logout so concurrent sessions for other evaluators/judges remain valid.
 */
export async function revokeSession(sessionId: string): Promise<void> {
  localRevokedSessions.add(sessionId);

  if (isRedisConnected()) {
    try {
      await redisSet(`revoked_session:${sessionId}`, '1', 8 * 3600);
    } catch {}
  }

  try {
    await prisma.session.updateMany({
      where: { id: sessionId },
      data: { revokedAt: new Date() }
    });
  } catch (error) {
    console.error('Failed to revoke session in DB:', error);
  }
}

/**
 * Revokes all sessions for a specific user.
 * Used on deactivation, role demotion, or administrative password reset.
 */
export async function revokeAllUserSessions(userId: string): Promise<void> {
  try {
    const activeSessions = await prisma.session.findMany({
      where: { userId, revokedAt: null },
      select: { id: true }
    });

    for (const s of activeSessions) {
      localRevokedSessions.add(s.id);
      if (isRedisConnected()) {
        redisSet(`revoked_session:${s.id}`, '1', 8 * 3600).catch(() => {});
      }
    }

    await prisma.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() }
    });
  } catch (error) {
    console.error('Failed to revoke all user sessions in DB:', error);
  }
}
