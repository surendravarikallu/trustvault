import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileTypeFromBuffer } from 'file-type';
import { config } from '../config.js';

// Ensure secure upload storage directory exists on startup
if (!fs.existsSync(config.uploadDir)) {
  fs.mkdirSync(config.uploadDir, { recursive: true, mode: 0o700 });
}

export interface StoredFileInfo {
  storedFilename: string;
  filePath: string;
  fileSize: number;
  fileHash: string;
  detectedMime: string;
}

/**
 * Validates file magic bytes against allowed types to prevent polyglot / disguised malware attacks
 */
export async function validateFileBuffer(buffer: Buffer, originalFilename: string, declaredMime: string): Promise<{ valid: boolean; detectedMime: string; error?: string }> {
  // Check extension against whitelist
  const ext = path.extname(originalFilename).toLowerCase();
  if (!config.allowedExtensions.includes(ext)) {
    return { valid: false, detectedMime: 'unknown', error: `File extension '${ext}' is not permitted.` };
  }

  // Inspect magic bytes using file-type
  const typeResult = await fileTypeFromBuffer(buffer);

  if (typeResult) {
    // If binary type detected, ensure it matches allowed types
    if (!config.allowedMimeTypes.includes(typeResult.mime)) {
      return {
        valid: false,
        detectedMime: typeResult.mime,
        error: `File signature mismatch or forbidden format detected: ${typeResult.mime}`
      };
    }
    return { valid: true, detectedMime: typeResult.mime };
  }

  // Plain text / CSV files don't have binary magic bytes in file-type
  if (['.txt', '.csv'].includes(ext)) {
    // Verify buffer does not contain null bytes (which indicate binary payloads disguised as text)
    const hasNullBytes = buffer.includes(0);
    if (hasNullBytes) {
      return { valid: false, detectedMime: 'application/octet-stream', error: 'Suspicious binary content in text file.' };
    }
    return { valid: true, detectedMime: ext === '.csv' ? 'text/csv' : 'text/plain' };
  }

  return { valid: false, detectedMime: 'unknown', error: 'Unable to verify file signature.' };
}

/**
 * Saves an uploaded file buffer to isolated storage with a random UUID identifier
 */
export async function saveFileBuffer(buffer: Buffer): Promise<StoredFileInfo> {
  const storedFilename = crypto.randomUUID();
  const filePath = path.join(config.uploadDir, storedFilename);

  // Compute SHA-256 hash of the content for tamper-proof document integrity
  const fileHash = crypto.createHash('sha256').update(buffer).digest('hex');

  await fs.promises.writeFile(filePath, buffer, { mode: 0o600 });

  return {
    storedFilename,
    filePath,
    fileSize: buffer.length,
    fileHash,
    detectedMime: 'application/octet-stream'
  };
}

/**
 * Retrieves the absolute path to a stored file, verifying it stays within the storage root
 */
export function getSafeFilePath(storedFilename: string): string | null {
  // Prevent any path traversal characters
  const sanitized = path.basename(storedFilename);
  const fullPath = path.join(config.uploadDir, sanitized);

  // Ensure full path is strictly inside uploadDir
  if (!fullPath.startsWith(config.uploadDir)) {
    return null;
  }

  if (!fs.existsSync(fullPath)) {
    return null;
  }

  return fullPath;
}

/**
 * Removes a file safely from disk
 */
export async function deleteFileFromStorage(storedFilename: string): Promise<boolean> {
  const filePath = getSafeFilePath(storedFilename);
  if (!filePath) return false;

  try {
    await fs.promises.unlink(filePath);
    return true;
  } catch (error) {
    console.error(`Failed to delete file ${storedFilename}:`, error);
    return false;
  }
}
