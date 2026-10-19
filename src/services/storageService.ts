import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { Readable, Transform } from 'stream';
import { config } from '../config';

const ENCRYPTION_MAGIC = Buffer.from('TV_AES256_GCM_v1:');
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

// Derive 32-byte storage master key
const STORAGE_KEY = crypto
  .createHash('sha256')
  .update(process.env.STORAGE_ENCRYPTION_KEY || config.jwtSecret + '_blob_at_rest_key_2026')
  .digest();

/**
 * Storage Service with Envelope Encryption (AES-256-GCM at rest).
 * Defense against Loophole L-17 & Unauthorized Physical Disk Access.
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
   * Stores a file buffer into vault storage with AES-256-GCM at-rest encryption.
   */
  public static async persistFile(tempFilePath: string): Promise<{ storedFilename: string; fileHash: string; fileSize: number }> {
    this.ensureDirs();
    const storedFilename = crypto.randomUUID();
    const targetPath = path.join(config.storageDir, storedFilename);

    const plaintext = await fs.promises.readFile(tempFilePath);
    const fileHash = crypto.createHash('sha256').update(plaintext).digest('hex');
    const fileSize = plaintext.length;

    // Encrypt at rest using AES-256-GCM
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, STORAGE_KEY, iv);

    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Packed envelope: [MAGIC (17)][IV (12)][AUTH_TAG (16)][CIPHERTEXT]
    const encryptedBlob = Buffer.concat([
      ENCRYPTION_MAGIC,
      iv,
      authTag,
      ciphertext
    ]);

    await fs.promises.writeFile(targetPath, encryptedBlob);

    return {
      storedFilename,
      fileHash,
      fileSize
    };
  }

  /**
   * Reads and decrypts a storage file buffer transparently.
   * Backward-compatible with unencrypted legacy/seed files.
   */
  public static async readDecryptedFile(filePath: string): Promise<Buffer> {
    const rawData = await fs.promises.readFile(filePath);

    // Check if file has encryption header
    if (rawData.length > ENCRYPTION_MAGIC.length && rawData.subarray(0, ENCRYPTION_MAGIC.length).equals(ENCRYPTION_MAGIC)) {
      let offset = ENCRYPTION_MAGIC.length;
      const iv = rawData.subarray(offset, offset + IV_LENGTH);
      offset += IV_LENGTH;
      const authTag = rawData.subarray(offset, offset + AUTH_TAG_LENGTH);
      offset += AUTH_TAG_LENGTH;
      const ciphertext = rawData.subarray(offset);

      const decipher = crypto.createDecipheriv(ALGORITHM, STORAGE_KEY, iv);
      decipher.setAuthTag(authTag);

      return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    }

    // Unencrypted legacy file
    return rawData;
  }

  /**
   * Returns a decrypted readable stream for streaming downloads.
   */
  public static createDecryptedReadStream(filePath: string): Readable {
    // For transparent streaming, if file is encrypted, we decrypt into stream
    const passThrough = new Transform({
      transform(chunk, _encoding, callback) {
        callback(null, chunk);
      }
    });

    this.readDecryptedFile(filePath)
      .then((decryptedBuffer) => {
        passThrough.end(decryptedBuffer);
      })
      .catch((err) => {
        passThrough.destroy(err);
      });

    return passThrough;
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
