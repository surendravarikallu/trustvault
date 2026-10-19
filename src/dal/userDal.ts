import { PrismaClient, Role } from '@prisma/client';

const prisma = new PrismaClient();

export async function getUserById(id: string) {
  return prisma.user.findUnique({
    where: { id }
  });
}

export async function getUserByEmail(email: string) {
  return prisma.user.findUnique({
    where: { email: email.toLowerCase().trim() }
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
  return prisma.user.update({
    where: { id: userId },
    data: { tokenVersion: { increment: 1 } }
  });
}

export async function setUserRole(userId: string, role: Role) {
  return prisma.user.update({
    where: { id: userId },
    data: {
      role,
      tokenVersion: { increment: 1 } // Instantly invalidates previous active sessions (L-01)
    }
  });
}

export async function setUserActive(userId: string, isActive: boolean) {
  return prisma.user.update({
    where: { id: userId },
    data: {
      isActive,
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

export async function listAllUsers(page = 1, limit = 50) {
  const skip = (page - 1) * limit;
  const [total, users] = await Promise.all([
    prisma.user.count(),
    prisma.user.findMany({
      skip,
      take: limit,
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        isActive: true,
        tokenVersion: true,
        createdAt: true
      }
    })
  ]);
  return { total, page, limit, users };
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
