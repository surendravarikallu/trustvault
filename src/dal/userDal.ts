import { Role, User as DbUser } from '@prisma/client';
import { prisma } from '../prisma';
import { invalidateUserSessionCache } from '../utils/sessionCache';

export async function getUserById(id: string): Promise<DbUser | null> {
  return prisma.user.findUnique({
    where: { id }
  });
}

export async function getUserByEmail(email: string): Promise<DbUser | null> {
  return prisma.user.findUnique({
    where: { email: email.toLowerCase().trim() }
  });
}

export async function getUserByEmailOrUsername(identifier: string): Promise<DbUser | null> {
  const cleanId = identifier.toLowerCase().trim();
  if (!cleanId) return null;

  if (cleanId.includes('@')) {
    return prisma.user.findUnique({
      where: { email: cleanId }
    });
  }

  return prisma.user.findFirst({
    where: {
      OR: [
        { email: cleanId },
        { email: `${cleanId}@trustvault.local` },
        { email: { startsWith: `${cleanId}@` } },
        { name: { equals: cleanId, mode: 'insensitive' } }
      ]
    }
  });
}

export async function createUser(data: {
  email: string;
  passwordHash: string;
  name: string;
  role?: Role;
}) {
  return prisma.user.create({
    data: {
      email: data.email.toLowerCase().trim(),
      passwordHash: data.passwordHash,
      name: data.name.trim(),
      role: data.role || Role.VIEWER,
      isActive: true,
      tokenVersion: 1
    }
  });
}

export async function incrementTokenVersion(userId: string) {
  invalidateUserSessionCache(userId);
  return prisma.user.update({
    where: { id: userId },
    data: { tokenVersion: { increment: 1 } }
  });
}

export async function setUserRole(userId: string, role: Role) {
  invalidateUserSessionCache(userId);
  return prisma.user.update({
    where: { id: userId },
    data: {
      role,
      tokenVersion: { increment: 1 } // Instantly invalidates previous active sessions (L-01)
    }
  });
}

export async function setUserActive(userId: string, isActive: boolean) {
  invalidateUserSessionCache(userId);
  return prisma.user.update({
    where: { id: userId },
    data: {
      isActive,
      tokenVersion: { increment: 1 } // Instantly invalidates previous active sessions (L-01)
    }
  });
}

export async function adminResetPassword(userId: string, passwordHash: string) {
  invalidateUserSessionCache(userId);
  return prisma.user.update({
    where: { id: userId },
    data: {
      passwordHash,
      tokenVersion: { increment: 1 } // Instantly invalidates previous active sessions (L-01)
    }
  });
}

export async function adminResetMfa(userId: string) {
  invalidateUserSessionCache(userId);
  return prisma.user.update({
    where: { id: userId },
    data: {
      mfaEnabled: false,
      mfaSecret: null,
      mfaBackupCodes: [],
      mfaLastTimeStep: null,
      tokenVersion: { increment: 1 } // Instantly invalidates previous active sessions (L-01)
    }
  });
}

export async function lookupUserByExactEmail(email: string) {
  return prisma.user.findUnique({
    where: { email: email.toLowerCase().trim() },
    select: {
      id: true,
      email: true,
      name: true,
      role: true
    }
  });
}

export async function listAllUsers(page = 1, limit = 100) {
  const skip = (page - 1) * limit;
  const [total, users] = await Promise.all([
    prisma.user.count(),
    prisma.user.findMany({
      skip,
      take: limit,
      orderBy: [
        { role: 'asc' }, // ADMIN first, then OWNER, then VIEWER
        { createdAt: 'desc' }
      ],
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isActive: true,
        tokenVersion: true,
        mfaEnabled: true,
        mfaSecret: true,
        createdAt: true
      }
    })
  ]);

  const sanitizedUsers = users.map(u => ({
    id: u.id,
    email: u.email,
    name: u.name,
    role: u.role,
    isActive: u.isActive,
    tokenVersion: u.tokenVersion,
    mfaEnabled: u.mfaEnabled,
    createdAt: u.createdAt
  }));

  return { total, page, limit, users: sanitizedUsers };
}

export async function getEligibleReviewers(excludeUserId: string) {
  return prisma.user.findMany({
    where: {
      id: { not: excludeUserId },
      isActive: true
    },
    select: {
      id: true,
      name: true,
      email: true,
      role: true
    },
    take: 10
  });
}

export async function setMfaPendingSecret(userId: string, encryptedSecret: string) {
  return prisma.user.update({
    where: { id: userId },
    data: { mfaSecret: encryptedSecret }
  });
}

export async function enableMfa(
  userId: string,
  hashedBackupCodes: string[],
  _lastTimeStep?: bigint
) {
  invalidateUserSessionCache(userId);
  return prisma.user.update({
    where: { id: userId },
    data: {
      mfaEnabled: true,
      mfaBackupCodes: hashedBackupCodes,
      mfaLastTimeStep: null, // Allow immediate first login in the current 30s window
      tokenVersion: { increment: 1 } // Invalidate old non-MFA sessions
    }
  });
}

export async function disableMfa(userId: string) {
  invalidateUserSessionCache(userId);
  return prisma.user.update({
    where: { id: userId },
    data: {
      mfaEnabled: false,
      mfaSecret: null,
      mfaBackupCodes: [],
      mfaLastTimeStep: null,
      tokenVersion: { increment: 1 } // Invalidate sessions on MFA disable
    }
  });
}

export async function getMfaState(userId: string) {
  return prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      email: true,
      name: true,
      role: true,
      tokenVersion: true,
      mfaEnabled: true,
      mfaSecret: true,
      mfaBackupCodes: true,
      mfaLastTimeStep: true
    }
  });
}

export async function recordMfaTimeStep(userId: string, timeStep: bigint) {
  return prisma.user.update({
    where: { id: userId },
    data: { mfaLastTimeStep: timeStep }
  });
}

export async function consumeMfaBackupCode(userId: string, consumedHash: string) {
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { mfaBackupCodes: true }
  });
  if (!user) return null;

  const remainingCodes = (user.mfaBackupCodes || []).filter((c: string) => c !== consumedHash);
  return prisma.user.update({
    where: { id: userId },
    data: { mfaBackupCodes: remainingCodes }
  });
}

