import { Prisma, Role, PermissionLevel, AuditStatus } from '@prisma/client';
import { prisma } from '../prisma';
import { logAuditEvent, logAccessDenied } from '../services/auditService';
import { StorageService } from '../services/storageService';
import { ActiveGrantContext } from './types';

export interface UserContext {
  id: string;
  email: string;
  name: string;
  role: Role;
}

export interface RequestContext {
  ip: string;
  userAgent: string;
  details?: string;
}

export interface SearchDocumentsParams {
  q?: string;         // Matches title or originalFilename
  owner?: string;     // Matches owner name or email
  category?: string;  // Category exact or prefix
  fromDate?: string;  // ISO timestamp (createdAt >= fromDate)
  toDate?: string;    // ISO timestamp (createdAt <= toDate)
}

export class NotFoundError extends Error {
  public statusCode = 404;
  constructor(message = 'Document not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}

export class ForbiddenError extends Error {
  public statusCode = 403;
  constructor(message = 'Access forbidden') {
    super(message);
    this.name = 'ForbiddenError';
  }
}

/**
 * Shared visibility predicate used across all document queries.
 * Eliminates authorization drift between list, search, and detail loading.
 */
export function visibleDocumentsWhere(user: UserContext): Prisma.DocumentWhereInput {
  if (user.role === Role.ADMIN) {
    // Admins have visibility over metadata for governance, but content downloads still require explicit grant.
    return { isDeleted: false };
  }

  const now = new Date();
  return {
    isDeleted: false,
    OR: [
      { ownerId: user.id },
      {
        permissions: {
          some: {
            userId: user.id,
            OR: [
              { expiresAt: null },
              { expiresAt: { gt: now } }
            ]
          }
        }
      }
    ]
  };
}

export type DocumentAction = 'read' | 'download' | 'edit' | 'delete' | 'manage_permissions';

/**
 * Single Gatekeeper for all document access.
 * Defense against Loophole L-19 (Mutation Resistance) & L-06 (404/403 Existence Oracle).
 */
export async function loadDocumentFor(
  user: UserContext,
  docId: string,
  action: DocumentAction,
  reqContext: RequestContext
) {
  const now = new Date();

  // 1. Fetch document with owner and caller's active permissions
  const doc = await prisma.document.findUnique({
    where: { id: docId },
    include: {
      owner: { select: { id: true, name: true, email: true } },
      permissions: {
        where: {
          userId: user.id,
          OR: [{ expiresAt: null }, { expiresAt: { gt: now } }]
        }
      }
    }
  });

  // If document does not exist or is soft-deleted
  if (!doc || doc.isDeleted) {
    await logAccessDenied(user, docId, action, reqContext);
    throw new NotFoundError();
  }

  const isOwner = doc.ownerId === user.id;
  const activeGrant: ActiveGrantContext | undefined = doc.permissions[0] as ActiveGrantContext | undefined; // Active grant for this user, if any
  const isAdmin = user.role === Role.ADMIN;
  const hasVisibility = isOwner || !!activeGrant || isAdmin;

  // 2. Information Leakage Protection (L-06):
  // If caller has ZERO visibility, return 404 (pretend the document does not exist).
  if (!hasVisibility) {
    await logAccessDenied(user, docId, action, reqContext);
    throw new NotFoundError();
  }

  // === MUTATION_POINT: AUTHORIZATION_CHECK ===
  // 3. Action-Specific Authorization Enforcement
  switch (action) {
    case 'read': {
      // Allowed for Owner, Active Grantee, or Admin
      await logAuditEvent({
        action: 'DOCUMENT_METADATA_READ',
        userId: user.id,
        userEmail: user.email,
        documentId: doc.id,
        documentTitle: doc.title,
        status: AuditStatus.SUCCESS,
        ipAddress: reqContext.ip,
        userAgent: reqContext.userAgent,
        details: `Read metadata for ${doc.title}`
      });
      return { document: doc };
    }

    case 'download': {
      // Loophole L-04: Admins cannot download contents without explicit grant
      if (isAdmin && !isOwner && !activeGrant) {
        await logAccessDenied(user, doc.id, action, {
          ...reqContext,
          details: 'Admins cannot download document content without an explicit grant from the owner.'
        });
        throw new ForbiddenError('Admins cannot download document content without an explicit grant from the owner.');
      }

      if (!isOwner && !activeGrant) {
        await logAccessDenied(user, doc.id, action, reqContext);
        throw new NotFoundError();
      }

      const filePath = StorageService.getSafeFilePath(doc.storedFilename);
      if (!filePath) {
        throw new NotFoundError('Storage file blob not found on disk.');
      }

      // Record fail-closed download audit
      await logAuditEvent({
        action: 'DOCUMENT_DOWNLOAD_STARTED',
        userId: user.id,
        userEmail: user.email,
        documentId: doc.id,
        documentTitle: doc.title,
        status: AuditStatus.SUCCESS,
        ipAddress: reqContext.ip,
        userAgent: reqContext.userAgent,
        details: `Downloaded file ${doc.originalFilename}`
      });

      return { document: doc, filePath, activeGrant };
    }

    case 'edit': {
      // Allowed if Owner OR Active Grantee with EDIT permission
      const canEdit = isOwner || (activeGrant && activeGrant.permissionLevel === PermissionLevel.EDIT);
      if (!canEdit) {
        await logAccessDenied(user, doc.id, action, {
          ...reqContext,
          details: 'Insufficient permissions: READ grantee attempted to edit document.'
        });
        throw new ForbiddenError('Insufficient permissions: only editors and owners can edit this document.');
      }
      return { document: doc };
    }

    case 'delete': {
      // Allowed only for Owner or Admin
      const canDelete = isOwner || isAdmin;
      if (!canDelete) {
        await logAccessDenied(user, doc.id, action, {
          ...reqContext,
          details: 'Non-owner attempted to delete document.'
        });
        throw new ForbiddenError('Only the document owner or system administrator can delete this document.');
      }
      return { document: doc };
    }

    case 'manage_permissions': {
      // Loophole L-03: Strictly Owner-only. Editors and Admins cannot re-share.
      if (!isOwner) {
        await logAccessDenied(user, doc.id, action, {
          ...reqContext,
          details: 'Unauthorized permission management attempt by non-owner.'
        });
        throw new ForbiddenError('Only the document owner can grant or revoke permissions.');
      }
      return { document: doc };
    }

    default:
      throw new ForbiddenError('Unrecognized document action.');
  }
}
const userGrantSelect = {
  permissionLevel: true,
  expiresAt: true,
  burnOnDownload: true,
  previewOnly: true,
  downloadCount: true
};

/**
 * Lists documents visible to the user with pagination
 */
export async function listDocuments(user: UserContext, page = 1, limit = 20) {
  const where = visibleDocumentsWhere(user);
  const skip = (page - 1) * limit;

  const [total, documents] = await Promise.all([
    prisma.document.count({ where }),
    prisma.document.findMany({
      where,
      skip,
      take: limit,
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        title: true,
        description: true,
        originalFilename: true,
        fileSize: true,
        mimeType: true,
        category: true,
        fileHash: true,
        createdAt: true,
        updatedAt: true,
        owner: { select: { id: true, name: true, email: true } },
        permissions: {
          where: { userId: user.id },
          select: userGrantSelect
        }
      }
    })
  ]);

  return { total, page, limit, documents };
}

/**
 * Searches documents scoped strictly within the visibility predicate.
 * Defense against Loophole L-07: Search Information Leakage.
 */
export async function searchDocuments(user: UserContext, params: SearchDocumentsParams) {
  const baseWhere = visibleDocumentsWhere(user);
  const andConditions: Prisma.DocumentWhereInput[] = [baseWhere];

  if (params.q && params.q.trim()) {
    const query = params.q.trim();
    andConditions.push({
      OR: [
        { title: { contains: query, mode: 'insensitive' } },
        { originalFilename: { contains: query, mode: 'insensitive' } },
        { description: { contains: query, mode: 'insensitive' } }
      ]
    });
  }

  if (params.owner && params.owner.trim()) {
    const ownerQuery = params.owner.trim();
    andConditions.push({
      owner: {
        OR: [
          { name: { contains: ownerQuery, mode: 'insensitive' } },
          { email: { contains: ownerQuery, mode: 'insensitive' } }
        ]
      }
    });
  }

  if (params.category && params.category.trim()) {
    andConditions.push({
      category: { equals: params.category.trim(), mode: 'insensitive' }
    });
  }

  if (params.fromDate) {
    const from = new Date(params.fromDate);
    if (!isNaN(from.getTime())) {
      andConditions.push({ createdAt: { gte: from } });
    }
  }

  if (params.toDate) {
    const to = new Date(params.toDate);
    if (!isNaN(to.getTime())) {
      andConditions.push({ createdAt: { lte: to } });
    }
  }

  const documents = await prisma.document.findMany({
    where: { AND: andConditions },
    take: 100,
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      title: true,
      description: true,
      originalFilename: true,
      fileSize: true,
      mimeType: true,
      category: true,
      fileHash: true,
      createdAt: true,
      updatedAt: true,
      owner: { select: { id: true, name: true, email: true } },
      permissions: {
        where: { userId: user.id },
        select: userGrantSelect
      }
    }
  });

  return documents;
}

/**
 * Soft deletes a document.
 */
export async function softDeleteDocument(user: UserContext, docId: string, reqContext: RequestContext) {
  const { document } = await loadDocumentFor(user, docId, 'delete', reqContext);

  await prisma.document.update({
    where: { id: document.id },
    data: {
      isDeleted: true,
      deletedAt: new Date()
    }
  });

  await logAuditEvent({
    action: 'DOCUMENT_DELETED',
    userId: user.id,
    userEmail: user.email,
    documentId: document.id,
    documentTitle: document.title,
    status: AuditStatus.SUCCESS,
    ipAddress: reqContext.ip,
    userAgent: reqContext.userAgent,
    details: `Soft-deleted document: ${document.title}`
  });

  return { success: true };
}

/**
 * Replaces a document file while preserving old version in DocumentVersion.
 * Defense against Loophole L-16: Irreversible File Overwrite.
 */
export async function createDocumentVersion(
  user: UserContext,
  docId: string,
  newFileData: {
    storedFilename: string;
    fileHash: string;
    fileSize: number;
    mimeType: string;
    originalFilename: string;
  },
  reqContext: RequestContext
) {
  const { document } = await loadDocumentFor(user, docId, 'edit', reqContext);

  return prisma.$transaction(async (tx) => {
    // 1. Get current version count
    const versionCount = await tx.documentVersion.count({
      where: { documentId: document.id }
    });
    const nextVersionNumber = versionCount + 1;

    // 2. Archive current blob in DocumentVersion
    await tx.documentVersion.create({
      data: {
        documentId: document.id,
        versionNumber: nextVersionNumber,
        storedFilename: document.storedFilename,
        fileSize: document.fileSize,
        fileHash: document.fileHash,
        uploadedById: user.id
      }
    });

    // 3. Update document with new blob
    const updated = await tx.document.update({
      where: { id: document.id },
      data: {
        storedFilename: newFileData.storedFilename,
        fileHash: newFileData.fileHash,
        fileSize: newFileData.fileSize,
        mimeType: newFileData.mimeType,
        originalFilename: newFileData.originalFilename
      }
    });

    // 4. Audit event
    await logAuditEvent(
      {
        action: 'DOCUMENT_VERSION_CREATED',
        userId: user.id,
        userEmail: user.email,
        documentId: document.id,
        documentTitle: document.title,
        status: AuditStatus.SUCCESS,
        ipAddress: reqContext.ip,
        userAgent: reqContext.userAgent,
        details: `Created version ${nextVersionNumber} replacing ${document.originalFilename}`
      },
      tx
    );

    return updated;
  });
}

/**
 * Creates a new document record.
 */
export async function createDocument(
  user: UserContext,
  data: {
    title: string;
    description?: string;
    originalFilename: string;
    storedFilename: string;
    fileSize: number;
    mimeType: string;
    category: string;
    fileHash: string;
  },
  reqContext: RequestContext
) {
  const doc = await prisma.document.create({
    data: {
      title: data.title.trim(),
      description: data.description ? data.description.trim() : null,
      originalFilename: data.originalFilename,
      storedFilename: data.storedFilename,
      fileSize: data.fileSize,
      mimeType: data.mimeType,
      category: data.category.trim(),
      fileHash: data.fileHash,
      ownerId: user.id
    }
  });

  await logAuditEvent({
    action: 'DOCUMENT_UPLOADED',
    userId: user.id,
    userEmail: user.email,
    documentId: doc.id,
    documentTitle: doc.title,
    status: AuditStatus.SUCCESS,
    ipAddress: reqContext.ip,
    userAgent: reqContext.userAgent,
    details: `Uploaded new document: ${doc.originalFilename} (${doc.fileSize} bytes)`
  });

  return doc;
}

/**
 * Retrieves version history. Restricted strictly to Document Owner (L-16 Redaction Protection).
 */
export async function getDocumentVersions(
  user: UserContext,
  docId: string,
  reqContext: RequestContext
) {
  const { document } = await loadDocumentFor(user, docId, 'manage_permissions', reqContext);

  const versions = await prisma.documentVersion.findMany({
    where: { documentId: document.id },
    orderBy: { versionNumber: 'desc' },
    select: {
      id: true,
      versionNumber: true,
      fileSize: true,
      fileHash: true,
      createdAt: true,
      uploadedById: true
    }
  });

  return versions;
}

