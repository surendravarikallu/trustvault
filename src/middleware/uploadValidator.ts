import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { Request, Response, NextFunction } from 'express';
import { config } from '../config';
import { validateDiskFile } from '../utils/fileSignature';

// Ensure temporary upload directory exists
if (!fs.existsSync(config.tempDir)) {
  fs.mkdirSync(config.tempDir, { recursive: true });
}

// Multer storage writing to storage/temp/
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, config.tempDir);
  },
  filename: (_req, file, cb) => {
    // Sanitize filename to prevent directory traversal
    const safeBaseName = path.basename(file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}_${safeBaseName}`);
  }
});

export const multerUpload = multer({
  storage,
  limits: {
    fileSize: 15 * 1024 * 1024 // 15 Megabytes maximum
  }
});

/**
 * Upload validation middleware.
 * Defense against Loophole L-15 (Disguised executables), L-17 (Path traversal), and L-18 (Windows EBUSY locks).
 */
export async function validateUploadedFile(req: Request, res: Response, next: NextFunction): Promise<void> {
  const file = req.file;

  if (!file) {
    res.status(400).json({ error: 'No file was uploaded.' });
    return;
  }

  // 1. Sanitize original filename (check for null bytes, CRLF header injection, or path traversal)
  if (
    file.originalname.includes('\0') ||
    file.originalname.includes('..') ||
    file.originalname.includes('\r') ||
    file.originalname.includes('\n') ||
    /[\x00-\x1f\x7f]/.test(file.originalname)
  ) {
    await safeUnlink(file.path);
    res.status(400).json({ error: 'Illegal characters, CRLF injection, or path traversal sequence in filename.' });
    return;
  }

  // 2. Magic byte buffer inspection
  try {
    const result = await validateDiskFile(file.path, file.originalname);
    if (!result.valid) {
      await safeUnlink(file.path);
      res.status(400).json({ error: `File validation failed: ${result.error}` });
      return;
    }

    // Attach validated MIME type
    (req as any).detectedMime = result.detectedMime;
    next();
  } catch (error: any) {
    await safeUnlink(file.path);
    res.status(500).json({ error: `Upload validation error: ${error.message}` });
  }
}

/**
 * Safely unlinks a file on Windows without crashing on brief locks.
 * Defense against Loophole L-18.
 */
export async function safeUnlink(filePath: string): Promise<void> {
  try {
    if (fs.existsSync(filePath)) {
      await fs.promises.unlink(filePath);
    }
  } catch (err) {
    // Suppress unlinking error to prevent crashing response lifecycle
    console.error(`Warning: Safe unlink could not remove ${filePath}:`, err);
  }
}
