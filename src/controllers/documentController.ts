import { Response } from 'express';
import { z } from 'zod';
import fs from 'fs';
import { Role } from '../dal/types';
import { AuthenticatedRequest } from '../middleware/auth';
import { StorageService } from '../services/storageService';
import { safeUnlink } from '../middleware/uploadValidator';
import {
  loadDocumentFor,
  listDocuments,
  searchDocuments,
  softDeleteDocument,
  createDocument,
  createDocumentVersion,
  getDocumentVersions,
  NotFoundError,
  ForbiddenError,
  RequestContext
} from '../dal/documentDal';
import { burnDocumentPermission } from '../dal/permissionDal';

export function getRequestContext(req: AuthenticatedRequest): RequestContext {
  const ip = (req.headers['cf-connecting-ip'] as string) || req.ip || req.socket.remoteAddress || '127.0.0.1';
  const userAgent = req.headers['user-agent'] || 'Unknown';
  return { ip, userAgent };
}

const CreateDocumentSchema = z.object({
  title: z.string().min(1, 'Title is required').max(255),
  description: z.string().optional(),
  category: z.string().min(1, 'Category is required').max(100)
});

export async function uploadDocument(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const file = req.file;

  if (!file) {
    res.status(400).json({ error: 'File upload is required.' });
    return;
  }

  // Loophole L-05: VIEWERs cannot upload documents
  if (user.role === Role.VIEWER) {
    await safeUnlink(file.path);
    res.status(403).json({ error: 'Viewers cannot upload documents. Owner promotion required.' });
    return;
  }

  const parseResult = CreateDocumentSchema.safeParse(req.body);
  if (!parseResult.success) {
    await safeUnlink(file.path);
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { title, description, category } = parseResult.data;
  const detectedMime = (req as any).detectedMime || 'application/octet-stream';

  let stored: { storedFilename: string; fileHash: string; fileSize: number } | null = null;

  try {
    // 1. Move file to permanent vault storage with opaque UUID
    stored = await StorageService.persistFile(file.path);

    // 2. Insert record via DAL
    const doc = await createDocument(
      user,
      {
        title,
        description,
        originalFilename: file.originalname,
        storedFilename: stored.storedFilename,
        fileSize: stored.fileSize,
        mimeType: detectedMime,
        category,
        fileHash: stored.fileHash
      },
      getRequestContext(req)
    );

    res.status(201).json({
      message: 'Document uploaded successfully.',
      document: doc,
      ...doc
    });
  } catch (error: any) {
    if (stored?.storedFilename) {
      await StorageService.deleteFile(stored.storedFilename);
    }
    res.status(500).json({ error: `Upload error: ${error.message}` });
  } finally {
    // Guaranteed temporary file cleanup (Loophole L-18)
    await safeUnlink(file.path);
  }
}

export async function getDocuments(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string, 10) || 20));

  try {
    const result = await listDocuments(user, page, limit);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function searchDocs(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { q, owner, category, fromDate, toDate } = req.query;

  try {
    const documents = await searchDocuments(user, {
      q: typeof q === 'string' ? q : undefined,
      owner: typeof owner === 'string' ? owner : undefined,
      category: typeof category === 'string' ? category : undefined,
      fromDate: typeof fromDate === 'string' ? fromDate : undefined,
      toDate: typeof toDate === 'string' ? toDate : undefined
    });

    res.json({ total: documents.length, documents });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function getDocumentById(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id } = req.params;

  if (id.includes('..') || id.includes('/') || id.includes('\\')) {
    res.status(400).json({ error: 'Path traversal sequence detected in document ID.' });
    return;
  }

  try {
    const { document } = await loadDocumentFor(user, id, 'read', getRequestContext(req));
    res.json({ document });
  } catch (error: any) {
    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
}

export async function downloadDocument(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id } = req.params;

  if (id.includes('..') || id.includes('/') || id.includes('\\')) {
    res.status(400).json({ error: 'Path traversal sequence detected in document ID.' });
    return;
  }

  try {
    const { document, filePath, activeGrant } = await loadDocumentFor(user, id, 'download', getRequestContext(req));

    if (!filePath || !fs.existsSync(filePath)) {
      res.status(404).json({ error: 'Stored file blob is missing.' });
      return;
    }

    const isPreview = req.query.preview === 'true' || req.query.is_preview === 'true';

    // Enforcement: If shared as Preview-Only, raw attachment downloads are prohibited
    if (activeGrant?.previewOnly && !isPreview) {
      res.status(403).json({
        error: 'This document was shared with In-Browser Preview Only restrictions. Binary file download is prohibited.'
      });
      return;
    }

    // Safe streaming headers with RFC 5987 Content-Disposition
    const encodedFilename = encodeURIComponent(document.originalFilename).replace(/['()]/g, escape);
    let effectiveMime = document.mimeType || 'application/octet-stream';
    const lowerFilename = document.originalFilename.toLowerCase();
    if (lowerFilename.endsWith('.pdf')) {
      effectiveMime = 'application/pdf';
    } else if (lowerFilename.endsWith('.txt')) {
      effectiveMime = 'text/plain';
    } else if (lowerFilename.endsWith('.json')) {
      effectiveMime = 'application/json';
    } else if (lowerFilename.endsWith('.png')) {
      effectiveMime = 'image/png';
    } else if (lowerFilename.endsWith('.jpg') || lowerFilename.endsWith('.jpeg')) {
      effectiveMime = 'image/jpeg';
    }

    res.setHeader('Content-Type', isPreview ? effectiveMime : 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    const dispositionType = isPreview ? 'inline' : 'attachment';
    res.setHeader(
      'Content-Disposition',
      `${dispositionType}; filename="${document.originalFilename.replace(/"/g, '')}"; filename*=UTF-8''${encodedFilename}`
    );

    // Enforcement: Burn-on-Download (One-Time Secure Transfer)
    // If the grant is marked burnOnDownload, automatically revoke access as soon as download completes
    if (activeGrant?.burnOnDownload && !isPreview) {
      res.on('finish', async () => {
        try {
          await burnDocumentPermission(document.id, user.id, user.email, getRequestContext(req));
        } catch (burnErr) {
          console.error('Failed to execute burn-on-download auto-revocation:', burnErr);
        }
      });
    }

    const stream = StorageService.createDecryptedReadStream(filePath);
    stream.on('error', (err) => {
      if (!res.headersSent) {
        res.status(500).json({ error: 'Failed to stream document.' });
      }
    });
    stream.pipe(res);
  } catch (error: any) {
    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: 'Internal server error.' });
    }
  }
}

export async function replaceDocumentFile(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id } = req.params;
  const file = req.file;

  if (!file) {
    res.status(400).json({ error: 'Replacement file is required.' });
    return;
  }

  let stored: { storedFilename: string; fileHash: string; fileSize: number } | null = null;

  try {
    // 1. Check edit authorization FIRST before moving file to permanent storage (CWE-400 defense)
    await loadDocumentFor(user, id, 'edit', getRequestContext(req));

    // 2. Persist to permanent storage only after authorization succeeds
    stored = await StorageService.persistFile(file.path);
    const detectedMime = (req as any).detectedMime || 'application/octet-stream';

    const updated = await createDocumentVersion(
      user,
      id,
      {
        storedFilename: stored.storedFilename,
        fileHash: stored.fileHash,
        fileSize: stored.fileSize,
        mimeType: detectedMime,
        originalFilename: file.originalname
      },
      getRequestContext(req)
    );

    res.json({
      message: 'New file version uploaded and previous version preserved in history.',
      document: updated
    });
  } catch (error: any) {
    // Clean up permanently stored file if database transaction failed
    if (stored?.storedFilename) {
      await StorageService.deleteFile(stored.storedFilename);
    }

    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: error.message });
    }
  } finally {
    await safeUnlink(file.path);
  }
}

export async function deleteDocument(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id } = req.params;

  try {
    await softDeleteDocument(user, id, getRequestContext(req));
    res.json({ message: 'Document soft-deleted successfully.' });
  } catch (error: any) {
    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
}

export async function getVersions(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id } = req.params;

  try {
    const versions = await getDocumentVersions(user, id, getRequestContext(req));
    res.json({ versions });
  } catch (error: any) {
    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
}
