import { PrismaClient, PermissionLevel, AuditStatus } from '@prisma/client';
import { logAuditEvent } from './auditDal';

const prisma = new PrismaClient();

export async function grantDocumentPermission(
  documentId: string,
  targetUserId: string,
  permissionLevel: PermissionLevel,
  expiresAt: Date | null,
  grantedBy: { id: string; email: string },
  reqContext: { ip: string; userAgent: string }
) {
  const result = await prisma.documentPermission.upsert({
    where: {
      documentId_userId: {
        documentId,
        userId: targetUserId
      }
    },
    update: {
      permissionLevel,
      expiresAt,
      grantedById: grantedBy.id,
      grantedAt: new Date()
    },
    create: {
      documentId,
      userId: targetUserId,
      permissionLevel,
      expiresAt,
      grantedById: grantedBy.id
    },
    include: {
      user: { select: { id: true, name: true, email: true } },
      document: { select: { id: true, title: true } }
    }
  });

  // Audit event
  await logAuditEvent({
    action: 'PERMISSION_GRANTED',
    userId: grantedBy.id,
    userEmail: grantedBy.email,
    documentId: result.document.id,
    documentTitle: result.document.title,
    status: AuditStatus.SUCCESS,
    ipAddress: reqContext.ip,
    userAgent: reqContext.userAgent,
    details: `Granted ${permissionLevel} access to user ${result.user.email} (Expires: ${expiresAt ? expiresAt.toISOString() : 'Never'})`
  });

  return result;
}

export async function revokeDocumentPermission(
  documentId: string,
  targetUserId: string,
  revokedBy: { id: string; email: string },
  reqContext: { ip: string; userAgent: string }
) {
  const existing = await prisma.documentPermission.findUnique({
    where: {
      documentId_userId: {
        documentId,
        userId: targetUserId
      }
    },
    include: {
      user: { select: { email: true } },
      document: { select: { title: true } }
    }
  });

  if (!existing) {
    return false;
  }

  await prisma.documentPermission.delete({
    where: {
      documentId_userId: {
        documentId,
        userId: targetUserId
      }
    }
  });

  // Audit event (Instant Revocation - L-02)
  await logAuditEvent({
    action: 'PERMISSION_REVOKED',
    userId: revokedBy.id,
    userEmail: revokedBy.email,
    documentId,
    documentTitle: existing.document.title,
    status: AuditStatus.SUCCESS,
    ipAddress: reqContext.ip,
    userAgent: reqContext.userAgent,
    details: `Revoked access from user ${existing.user.email}`
  });

  return true;
}

export async function getGranteesForDocument(documentId: string) {
  return prisma.documentPermission.findMany({
    where: { documentId },
    include: {
      user: { select: { id: true, name: true, email: true, role: true } },
      grantedBy: { select: { id: true, name: true, email: true } }
    },
    orderBy: { grantedAt: 'desc' }
  });
}
