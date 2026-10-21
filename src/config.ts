import path from 'path';
import dotenv from 'dotenv';

dotenv.config();

export const config = {
  port: parseInt(process.env.PORT || '7777', 10),
  nodeEnv: process.env.NODE_ENV || 'development',
  jwtSecret: process.env.JWT_SECRET || 'trustvault_jwt_secret_dev_key_2026_super_secure',
  auditHmacSecret: process.env.AUDIT_HMAC_SECRET || 'trustvault_hmac_secret_dev_key_2026_super_secure',
  storageEncryptionKey: process.env.STORAGE_ENCRYPTION_KEY || 'trustvault_storage_aes256_master_key_2026_super_secure',
  storageDir: path.resolve(process.env.STORAGE_DIR || 'storage/uploads'),
  tempDir: path.resolve(process.env.TEMP_DIR || 'storage/temp'),
  anchorFile: path.resolve(process.env.NODE_ENV === 'test' ? (process.env.TEST_ANCHOR_FILE || 'storage/audit_anchor_test.json') : (process.env.ANCHOR_FILE || 'storage/audit_anchor.json')),
  redisUrl: process.env.REDIS_URL || 'redis://:TrustVault_Redis_2026_SecureKey!@127.0.0.1:6385',
  databaseUrl: process.env.DATABASE_URL || 'postgresql://postgres:admin@localhost:5432/trustvault',
  appDatabaseUrl: process.env.APP_DATABASE_URL || 'postgresql://trustvault_app:app_secure_password@localhost:5432/trustvault',
  testDatabaseUrl: process.env.TEST_DATABASE_URL || 'postgresql://postgres:admin@localhost:5432/trustvault_test'
};
