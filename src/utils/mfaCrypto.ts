import crypto from 'crypto';
import { config } from '../config';

// Derive 32-byte AES key using SHA-256
const MASTER_KEY = crypto
  .createHash('sha256')
  .update(process.env.MFA_ENCRYPTION_KEY || config.jwtSecret + '_mfa_vault_encryption_2026')
  .digest();

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // Standard 96-bit IV for GCM

/**
 * Encrypts an MFA base32 secret before storing in PostgreSQL.
 * Format: iv:authTag:ciphertext (hex encoded)
 */
export function encryptMfaSecret(plaintext: string): string {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, MASTER_KEY, iv);
  
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypts an encrypted MFA secret retrieved from PostgreSQL.
 */
export function decryptMfaSecret(payload: string): string {
  const parts = payload.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted MFA secret format.');
  }

  const [ivHex, authTagHex, encryptedHex] = parts;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, MASTER_KEY, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Computes current 30-second Unix time step
 */
export function getCurrentTotpTimeStep(): bigint {
  return BigInt(Math.floor(Date.now() / 30000));
}

/**
 * Generates 8 random single-use recovery backup codes
 */
export function generateBackupCodes(): { rawCodes: string[]; hashedCodes: string[] } {
  const rawCodes: string[] = [];
  const hashedCodes: string[] = [];

  for (let i = 0; i < 8; i++) {
    // Generate an 8-character uppercase alphanumeric code: e.g. "A3F8-9C2D"
    const part1 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const part2 = crypto.randomBytes(2).toString('hex').toUpperCase();
    const code = `${part1}-${part2}`;
    
    rawCodes.push(code);
    const hash = crypto.createHash('sha256').update(code).digest('hex');
    hashedCodes.push(hash);
  }

  return { rawCodes, hashedCodes };
}
