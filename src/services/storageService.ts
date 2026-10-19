import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { config } from '../config';

/**
 * Storage Service for encrypted/opaque local disk blobs.
 * Defense against Loophole L-17: Direct Storage URL Access & Path Traversal.
 */
export class StorageService {
  private static ensureDirs(): void {
    if (!fs.existsSync(config.storageDir)) {
      fs.mkdirSync(config.storageDir, { recursive: true });
    }
    if (!fs.existsSync(config.tempDir)) {
      fs.mkdirSync(config.tempDir, { recursive: true });
    }
  }

  /**
   * Generates a safe, opaque disk file path from stored UUID filename.
   * Strips path traversal characters (../, ..\, etc.)
   */
  public static getSafeFilePath(storedFilename: string): string | null {
    this.ensureDirs();
    const sanitized = path.basename(storedFilename);
    const fullPath = path.join(config.storageDir, sanitized);

    // Verify path remains strictly inside storageDir
    if (!fullPath.startsWith(config.storageDir)) {
      return null;
    }
    return fullPath;
  }

  /**
   * Stores a file buffer or moves a temp file into vault storage
   */
  public static async persistFile(tempFilePath: string): Promise<{ storedFilename: string; fileHash: string; fileSize: number }> {
    this.ensureDirs();
    const storedFilename = crypto.randomUUID();
    const targetPath = path.join(config.storageDir, storedFilename);

    const buffer = await fs.promises.readFile(tempFilePath);
    const fileHash = crypto.createHash('sha256').update(buffer).digest('hex');
    const fileSize = buffer.length;

    await fs.promises.copyFile(tempFilePath, targetPath);

    return {
      storedFilename,
      fileHash,
      fileSize
    };
  }

  /**
   * Removes a file from storage safely
   */
  public static async deleteFile(storedFilename: string): Promise<boolean> {
    const fullPath = this.getSafeFilePath(storedFilename);
    if (!fullPath || !fs.existsSync(fullPath)) {
      return false;
    }
    try {
      await fs.promises.unlink(fullPath);
      return true;
    } catch (err) {
      console.error(`Failed to delete storage file ${storedFilename}:`, err);
      return false;
    }
  }
}
