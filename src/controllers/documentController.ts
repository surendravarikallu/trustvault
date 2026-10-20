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
import { recordDownloadAndEnforceQuota, burnDocumentPermission } from '../dal/permissionDal';
import { applyForensicWatermark, protectPdfWithPassword } from '../utils/pdfEngine';
import bcrypt from 'bcrypt';

import net from 'net';

/**
 * Sanitizes and securely resolves client IP and User-Agent.
 * Defends against Header-Based IP Spoofing & Audit Log Poisoning (CWE-290 - Threat T-51).
 */
export function getRequestContext(req: AuthenticatedRequest): RequestContext {
  const socketIp = req.socket.remoteAddress || '';
  const isLoopbackOrLocal =
    socketIp === '127.0.0.1' ||
    socketIp === '::1' ||
    socketIp === '::ffff:127.0.0.1' ||
    socketIp.startsWith('10.') ||
    socketIp.startsWith('172.16.') ||
    socketIp.startsWith('192.168.');

  let resolvedIp = '';

  // Only trust proxy-provided headers if direct socket connection is from trusted local loopback/proxy
  if (isLoopbackOrLocal) {
    const cfIp = req.headers['cf-connecting-ip'];
    const xff = req.headers['x-forwarded-for'];

    if (typeof cfIp === 'string') {
      const candidate = cfIp.trim();
      if (net.isIP(candidate)) {
        resolvedIp = candidate;
      }
    }

    if (!resolvedIp && typeof xff === 'string') {
      const firstIp = xff.split(',')[0].trim();
      if (net.isIP(firstIp)) {
        resolvedIp = firstIp;
      }
    }
  }

  // Fallback to Express evaluated req.ip or raw socket address
  if (!resolvedIp) {
    const rawIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
    const cleanRaw = rawIp.replace(/^::ffff:/, '').trim();
    resolvedIp = net.isIP(cleanRaw) ? cleanRaw : '127.0.0.1';
  }

  const rawUa = (req.headers['user-agent'] || 'Unknown').toString();
  // Strip non-printable control characters to prevent terminal escape injection in logs
  const sanitizedUa = rawUa.replace(/[\x00-\x1F\x7F]/g, '').slice(0, 512);

  return { ip: resolvedIp, userAgent: sanitizedUa };
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

    // Enforcement: Download Quota Check
    if (activeGrant && activeGrant.downloadCount !== undefined && typeof activeGrant.maxDownloads === 'number' && activeGrant.maxDownloads > 0 && activeGrant.downloadCount >= activeGrant.maxDownloads) {
      res.status(404).json({ error: 'Document not found.' });
      return;
    }

    // Enforcement: PDF Password / One-Time Password (OTP) verification
    const otpProvided = (req.headers['x-pdf-otp'] as string) || (req.query.otp as string);
    if (activeGrant?.pdfProtected && activeGrant.otpHash && !isPreview) {
      if (!otpProvided) {
        res.status(401).json({
          pdfProtected: true,
          error: 'This PDF is password-protected. Please provide the OTP via header x-pdf-otp or query parameter otp.'
        });
        return;
      }

      const isOtpValid = await bcrypt.compare(otpProvided.trim(), activeGrant.otpHash);
      if (!isOtpValid) {
        res.status(401).json({
          pdfProtected: true,
          error: 'Invalid OTP password provided for this protected PDF.'
        });
        return;
      }
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

    // Dynamic Delivery for PDFs: Forensic Watermarking and Password Encryption
    if (lowerFilename.endsWith('.pdf') && (activeGrant || !isPreview)) {
      let fileBuffer = await StorageService.readDecryptedFile(filePath);

      // Apply dynamic forensic watermark for grantee or if customized
      const isGrantee = !!activeGrant && document.ownerId !== user.id;
      if (isGrantee || activeGrant?.watermarkText) {
        try {
          fileBuffer = await applyForensicWatermark(fileBuffer, {
            recipientEmail: user.email,
            ipAddress: req.ip,
            customText: activeGrant?.watermarkText || undefined,
            grantId: activeGrant?.id
          });
        } catch (wmErr) {
          console.error('Failed to apply watermark, serving original:', wmErr);
        }
      }

      // Apply user open password protection if pdfProtected is true
      if (activeGrant?.pdfProtected && otpProvided) {
        try {
          fileBuffer = await protectPdfWithPassword(fileBuffer, otpProvided.trim());
        } catch (encErr) {
          console.error('Failed to apply PDF password encryption:', encErr);
        }
      }

      // Enforcement: Bounded Multi-Download Quota / Burn-on-Download
      if (activeGrant && !isPreview) {
        res.on('finish', async () => {
          try {
            await recordDownloadAndEnforceQuota(document.id, user.id, user.email, getRequestContext(req));
          } catch (burnErr) {
            console.error('Failed to enforce download quota:', burnErr);
          }
        });
      }

      res.setHeader('Content-Length', fileBuffer.length);
      res.end(fileBuffer);
      return;
    }

    // Enforcement: Bounded Multi-Download Quota / Burn-on-Download for non-PDF files
    if (activeGrant && !isPreview) {
      res.on('finish', async () => {
        try {
          await recordDownloadAndEnforceQuota(document.id, user.id, user.email, getRequestContext(req));
        } catch (burnErr) {
          console.error('Failed to enforce download quota:', burnErr);
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
