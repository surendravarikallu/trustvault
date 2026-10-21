import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

const nodeEnv = process.env.NODE_ENV || 'development';
const isProd = nodeEnv === 'production';

function requireEnvInProd(key: string, devDefault?: string): string {
  const val = process.env[key];
  if (!val) {
    if (isProd || devDefault === undefined) {
      throw new Error(`CRITICAL CONFIGURATION ERROR: Missing required environment variable '${key}'.`);
    }
    return devDefault;
  }
  return val;
}

export const config = {
  port: parseInt(process.env.PORT || '7777', 10),
  nodeEnv,
  jwtSecret: requireEnvInProd('JWT_SECRET', 'trustvault_jwt_secret_dev_key_2026_super_secure'),
  auditHmacSecret: requireEnvInProd('AUDIT_HMAC_SECRET', 'trustvault_hmac_secret_dev_key_2026_super_secure'),
  storageEncryptionKey: requireEnvInProd('STORAGE_ENCRYPTION_KEY', 'trustvault_storage_aes256_master_key_2026_super_secure'),
  storageDir: path.resolve(process.env.STORAGE_DIR || 'storage/uploads'),
  tempDir: path.resolve(process.env.TEMP_DIR || 'storage/temp'),
  anchorFile: path.resolve(nodeEnv === 'test' ? (process.env.TEST_ANCHOR_FILE || 'storage/audit_anchor_test.json') : (process.env.ANCHOR_FILE || 'storage/audit_anchor.json')),
  redisUrl: process.env.REDIS_URL || 'redis://127.0.0.1:6385',
  databaseUrl: process.env.DATABASE_URL || '',
  appDatabaseUrl: isProd ? requireEnvInProd('APP_DATABASE_URL') : (process.env.APP_DATABASE_URL || process.env.DATABASE_URL || ''),
  testDatabaseUrl: process.env.TEST_DATABASE_URL || ''
};
