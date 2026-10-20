import { PermissionLevel, AuditStatus } from '@prisma/client';
import { prisma } from '../prisma';
import { logAuditEvent } from './auditDal';

export async function grantDocumentPermission(
  documentId: string,
  targetUserId: string,
  permissionLevel: PermissionLevel,
  expiresAt: Date | null,
  grantedBy: { id: string; email: string },
  reqContext: { ip: string; userAgent: string },
  options?: {
    burnOnDownload?: boolean;
    previewOnly?: boolean;
    maxDownloads?: number;
    pdfProtected?: boolean;
    otpHash?: string | null;
    watermarkText?: string | null;
  }
) {
  const burnOnDownload = options?.burnOnDownload ?? false;
  const previewOnly = options?.previewOnly ?? false;
  const maxDownloads = options?.maxDownloads ?? (burnOnDownload ? 1 : 0);
  const pdfProtected = options?.pdfProtected ?? false;
  const otpHash = options?.otpHash ?? null;
  const watermarkText = options?.watermarkText ?? null;

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
      burnOnDownload,
      maxDownloads,
      previewOnly,
      pdfProtected,
      otpHash,
      watermarkText,
      downloadCount: 0,
      grantedById: grantedBy.id,
      grantedAt: new Date()
    },
    create: {
      documentId,
      userId: targetUserId,
      permissionLevel,
      expiresAt,
      burnOnDownload,
      maxDownloads,
      previewOnly,
      pdfProtected,
      otpHash,
      watermarkText,
      downloadCount: 0,
      grantedById: grantedBy.id
    },
    include: {
      user: { select: { id: true, name: true, email: true } },
      document: { select: { id: true, title: true } }
    }
  });

  const traits: string[] = [];
  if (burnOnDownload) traits.push('Burn-on-Download: Enabled (Single-Use)');
  else if (maxDownloads > 1) traits.push(`Max Downloads Quota: ${maxDownloads}`);
  if (pdfProtected) traits.push('PDF Password/OTP Protection: Enabled');
  if (watermarkText) traits.push(`Watermark: ${watermarkText}`);
  if (previewOnly) traits.push('In-Browser Preview Only');
  if (expiresAt) traits.push(`Expires: ${expiresAt.toISOString()}`);
  const traitStr = traits.length > 0 ? ` [${traits.join(', ')}]` : '';

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
    details: `Granted ${permissionLevel} access to user ${result.user.email}${traitStr}`
  });

  return result;
}

export async function burnDocumentPermission(
  documentId: string,
  userId: string,
  userEmail: string,
  reqContext: { ip: string; userAgent: string }
) {
  const perm = await prisma.documentPermission.findUnique({
    where: {
      documentId_userId: { documentId, userId }
    },
    include: {
      document: { select: { title: true } }
    }
  });

  if (!perm) return false;

  await prisma.documentPermission.delete({
    where: {
      documentId_userId: { documentId, userId }
    }
  });

  await logAuditEvent({
    action: 'PERMISSION_BURNED_AFTER_DOWNLOAD',
    userId,
    userEmail,
    documentId,
    documentTitle: perm.document.title,
    status: AuditStatus.SUCCESS,
    ipAddress: reqContext.ip,
    userAgent: reqContext.userAgent,
    details: `Burn-on-Download executed: single-use grant for ${userEmail} automatically self-destructed following download.`
  });

  return true;
}

export async function recordDownloadAndEnforceQuota(
  documentId: string,
  userId: string,
  userEmail: string,
  reqContext: { ip: string; userAgent: string }
): Promise<{ burned: boolean; remainingDownloads: number }> {
  const perm = await prisma.documentPermission.findUnique({
    where: {
      documentId_userId: { documentId, userId }
    },
    include: {
      document: { select: { title: true } }
    }
  });

  if (!perm) return { burned: false, remainingDownloads: 0 };

  const newDownloadCount = perm.downloadCount + 1;
  const maxDownloads = perm.maxDownloads;
  const hasQuota = typeof maxDownloads === 'number' && maxDownloads > 0;
  const shouldBurn = perm.burnOnDownload || (hasQuota && newDownloadCount >= maxDownloads);

  if (shouldBurn) {
    await prisma.documentPermission.delete({
      where: {
        documentId_userId: { documentId, userId }
      }
    });

    await logAuditEvent({
      action: perm.burnOnDownload ? 'PERMISSION_BURNED_AFTER_DOWNLOAD' : 'PERMISSION_QUOTA_EXHAUSTED',
      userId,
      userEmail,
      documentId,
      documentTitle: perm.document.title,
      status: AuditStatus.SUCCESS,
      ipAddress: reqContext.ip,
      userAgent: reqContext.userAgent,
      details: perm.burnOnDownload
        ? `Burn-on-Download executed: single-use grant for ${userEmail} automatically self-destructed following download.`
        : `Download quota exhausted (${newDownloadCount}/${maxDownloads}): grant for ${userEmail} automatically self-destructed.`
    });

    return { burned: true, remainingDownloads: 0 };
  } else {
    await prisma.documentPermission.update({
      where: {
        documentId_userId: { documentId, userId }
      },
      data: {
        downloadCount: { increment: 1 }
      }
    });

    const remaining = maxDownloads - newDownloadCount;
    await logAuditEvent({
      action: 'DOCUMENT_DOWNLOADED_QUOTA_REMAINING',
      userId,
      userEmail,
      documentId,
      documentTitle: perm.document.title,
      status: AuditStatus.SUCCESS,
      ipAddress: reqContext.ip,
      userAgent: reqContext.userAgent,
      details: `Document downloaded by ${userEmail}. Remaining downloads allowed: ${remaining}/${maxDownloads}.`
    });

    return { burned: false, remainingDownloads: remaining };
  }
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
