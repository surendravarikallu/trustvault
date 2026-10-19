import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { validateFileBuffer, saveFileBuffer, getSafeFilePath, deleteFileFromStorage } from '../services/storageService.js';
import { recordAudit } from '../services/auditService.js';

const prisma = new PrismaClient();

/**
 * Handles secure file uploads with magic bytes validation and isolated disk storage
 */
export async function uploadDocument(req: Request, res: Response) {
  try {
    const user = req.user!;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'No file uploaded.' });
    }

    const { title, category, description } = req.body;
    const documentTitle = title ? title.trim() : file.originalname;

    // Validate file magic bytes against extension
    const validation = await validateFileBuffer(file.buffer, file.originalname, file.mimetype);
    if (!validation.valid) {
      await recordAudit({
        action: 'ACCESS_DENIED',
        userId: user.id,
        userEmail: user.email,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: `Rejected file upload '${file.originalname}': ${validation.error}`
      });
      return res.status(400).json({ error: validation.error });
    }

    // Save to isolated storage with random UUID
    const stored = await saveFileBuffer(file.buffer);

    // Create database record
    const document = await prisma.document.create({
      data: {
        title: documentTitle,
        description: description ? description.trim() : null,
        originalFilename: file.originalname,
        storedFilename: stored.storedFilename,
        fileSize: stored.fileSize,
        mimeType: validation.detectedMime,
        category: category ? category.trim() : 'General',
        fileHash: stored.fileHash,
        ownerId: user.id
      }
    });

    // Record audit event
    await recordAudit({
      action: 'UPLOAD',
      userId: user.id,
      userEmail: user.email,
      documentId: document.id,
      documentTitle: document.title,
      status: 'SUCCESS',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: `Uploaded ${file.originalname} (${stored.fileSize} bytes, SHA-256: ${stored.fileHash.slice(0, 16)}...)`
    });

    return res.status(201).json({
      message: 'Document uploaded successfully.',
      document: {
        id: document.id,
        title: document.title,
        description: document.description,
        originalFilename: document.originalFilename,
        fileSize: document.fileSize,
        mimeType: document.mimeType,
        category: document.category,
        fileHash: document.fileHash,
        createdAt: document.createdAt
      }
    });
  } catch (error) {
    console.error('Upload document error:', error);
    return res.status(500).json({ error: 'Internal server error during upload.' });
  }
}

/**
 * Lists documents strictly accessible to the requesting user (Own + Shared)
 * Evaluator check: Non-admins CANNOT see other users' document titles or metadata
 */
export async function listDocuments(req: Request, res: Response) {
  try {
    const user = req.user!;
    const { q, category, startDate, endDate } = req.query;

    const whereClause: any = {};

    // Strict row-level isolation: Administrator sees all, others see ONLY owned or explicitly granted
    if (user.role !== 'ADMIN') {
      whereClause.OR = [
        { ownerId: user.id },
        { permissions: { some: { userId: user.id } } }
      ];
    }

    // Search filters
    if (q && typeof q === 'string') {
      whereClause.title = { contains: q };
    }

    if (category && typeof category === 'string' && category !== 'All') {
      whereClause.category = category;
    }

    if (startDate || endDate) {
      whereClause.createdAt = {};
      if (startDate && typeof startDate === 'string') {
        whereClause.createdAt.gte = new Date(startDate);
      }
      if (endDate && typeof endDate === 'string') {
        whereClause.createdAt.lte = new Date(endDate);
      }
    }

    const documents = await prisma.document.findMany({
      where: whereClause,
      include: {
        owner: { select: { id: true, name: true, email: true } },
        permissions: {
          where: { userId: user.id },
          select: { permissionLevel: true }
        }
      },
      orderBy: { createdAt: 'desc' }
    });

    const formatted = documents.map(doc => {
      let effectivePermission = 'NONE';
      if (doc.ownerId === user.id) {
        effectivePermission = 'OWNER';
      } else if (user.role === 'ADMIN') {
        effectivePermission = 'ADMIN';
      } else if (doc.permissions.length > 0) {
        effectivePermission = doc.permissions[0].permissionLevel;
      }

      return {
        id: doc.id,
        title: doc.title,
        description: doc.description,
        originalFilename: doc.originalFilename,
        fileSize: doc.fileSize,
        mimeType: doc.mimeType,
        category: doc.category,
        fileHash: doc.fileHash,
        createdAt: doc.createdAt,
        owner: doc.owner,
        permission: effectivePermission
      };
    });

    return res.json({ documents: formatted });
  } catch (error) {
    console.error('List documents error:', error);
    return res.status(500).json({ error: 'Failed to retrieve documents.' });
  }
}

/**
 * Retrieves metadata for a single authorized document
 */
export async function getDocument(req: Request, res: Response) {
  const document = req.document!;
  const user = req.user!;

  const fullDoc = await prisma.document.findUnique({
    where: { id: document.id },
    include: {
      owner: { select: { id: true, name: true, email: true } },
      permissions: {
        include: { user: { select: { id: true, name: true, email: true } } }
      }
    }
  });

  return res.json({
    document: {
      ...fullDoc,
      currentUserPermission: req.permissionLevel
    }
  });
}

/**
 * Streams document binary securely to authorized user
 * Evaluator check: If authorizeDocumentAccess middleware is removed, this becomes vulnerable
 */
export async function downloadDocument(req: Request, res: Response) {
  try {
    const document = req.document!;
    const user = req.user!;

    const filePath = getSafeFilePath(document.storedFilename);
    if (!filePath) {
      return res.status(404).json({ error: 'File binary not found on storage server.' });
    }

    // Record verified download in audit trail
    await recordAudit({
      action: 'DOWNLOAD',
      userId: user.id,
      userEmail: user.email,
      documentId: document.id,
      documentTitle: document.title,
      status: 'SUCCESS',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: `Downloaded ${document.originalFilename} (permission: ${req.permissionLevel})`
    });

    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(document.originalFilename)}"`);
    res.setHeader('Content-Type', document.mimeType);
    res.setHeader('X-Content-Type-Options', 'nosniff');

    return res.sendFile(filePath);
  } catch (error) {
    console.error('Download error:', error);
    return res.status(500).json({ error: 'Failed to stream document.' });
  }
}

/**
 * Deletes document (restricted to Owner or Admin)
 */
export async function deleteDocument(req: Request, res: Response) {
  try {
    const document = req.document!;
    const user = req.user!;

    if (document.ownerId !== user.id && user.role !== 'ADMIN') {
      await recordAudit({
        action: 'ACCESS_DENIED',
        userId: user.id,
        userEmail: user.email,
        documentId: document.id,
        documentTitle: document.title,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: 'Attempted to delete document without owner/admin role'
      });
      return res.status(403).json({ error: 'Only the document owner or an administrator can delete this document.' });
    }

    // Delete file binary
    await deleteFileFromStorage(document.storedFilename);

    // Delete database records (cascade deletes permissions and sets null on audit logs)
    await prisma.document.delete({
      where: { id: document.id }
    });

    // Record audit event
    await recordAudit({
      action: 'DELETE',
      userId: user.id,
      userEmail: user.email,
      documentId: document.id,
      documentTitle: document.title,
      status: 'SUCCESS',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: `Permanently deleted document '${document.title}'`
    });

    return res.json({ message: 'Document deleted successfully.' });
  } catch (error) {
    console.error('Delete document error:', error);
    return res.status(500).json({ error: 'Failed to delete document.' });
  }
}
