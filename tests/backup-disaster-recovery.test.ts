import { describe, it, expect, beforeAll } from '@jest/globals';
import request from 'supertest';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { app } from '../src/server';
import { BackupService } from '../src/services/backupService';
import { StorageService } from '../src/services/storageService';

import { extractAuthCookie } from './testAuth';

let adminCookie: string;
let viewerCookie: string;

beforeAll(async () => {
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.local', password: 'Admin@TrustVault2026!' });
  expect(adminRes.status).toBe(200);
  adminCookie = extractAuthCookie(adminRes);

  const viewerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'viewer@trustvault.local', password: 'Viewer@TrustVault2026!' });
  expect(viewerRes.status).toBe(200);
  viewerCookie = extractAuthCookie(viewerRes);
});

describe('Disaster Recovery, Cryptographic Backups & Storage Encryption Suite', () => {
  it('DR-01: Deep health check endpoint returns DB round-trip latency, memory stats and uptime', async () => {
    const res = await request(app).get('/api/health');

    expect(res.status).toBe(200);
    expect(res.body.status).toBe('healthy');
    expect(res.body.system).toBe('TrustVault Zero-Trust Security Engine');
    expect(res.body.database).toBeDefined();
    expect(res.body.database.status).toBe('connected');
    expect(typeof res.body.database.latencyMs).toBe('number');
    expect(res.body.database.latencyMs).toBeGreaterThanOrEqual(0);
    expect(res.body.memory).toBeDefined();
    expect(res.body.memory.heapUsedMb).toBeGreaterThan(0);
    expect(res.body.uptimeSeconds).toBeGreaterThanOrEqual(0);
  });

  it('DR-02: Envelope Encryption At Rest encrypts files with AES-256-GCM and header verification', async () => {
    const tempDir = path.resolve(process.cwd(), 'storage/temp');
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    const testSecretData = Buffer.from('CONFIDENTIAL_AT_REST_DATA_' + crypto.randomBytes(32).toString('hex'), 'utf8');
    const tempFilePath = path.join(tempDir, `encrypt_test_${Date.now()}.txt`);
    fs.writeFileSync(tempFilePath, testSecretData);

    // 1. Persist file through StorageService
    const stored = await StorageService.persistFile(tempFilePath);
    expect(stored.storedFilename).toBeDefined();

    const storedPath = StorageService.getSafeFilePath(stored.storedFilename);
    expect(storedPath).toBeTruthy();
    expect(fs.existsSync(storedPath!)).toBe(true);

    // 2. Verify on-disk file has TV_AES256_GCM_v1: header and ciphertext does not match plaintext
    const rawDiskBytes = fs.readFileSync(storedPath!);
    const magicHeader = Buffer.from('TV_AES256_GCM_v1:', 'utf8');
    expect(rawDiskBytes.subarray(0, magicHeader.length).equals(magicHeader)).toBe(true);
    expect(rawDiskBytes.includes(testSecretData)).toBe(false);

    // 3. Verify transparent decryption via readDecryptedFile
    const decryptedBytes = await StorageService.readDecryptedFile(storedPath!);
    expect(decryptedBytes.equals(testSecretData)).toBe(true);

    // 4. Verify streaming decryption via createDecryptedReadStream
    const stream = StorageService.createDecryptedReadStream(storedPath!);
    const chunks: Buffer[] = [];
    await new Promise<void>((resolve, reject) => {
      stream.on('data', (c) => chunks.push(Buffer.from(c)));
      stream.on('end', () => resolve());
      stream.on('error', reject);
    });
    const streamedData = Buffer.concat(chunks);
    expect(streamedData.equals(testSecretData)).toBe(true);

    // 5. Cleanup
    await StorageService.deleteFile(stored.storedFilename);
  });

  it('DR-03: Backward compatibility with unencrypted legacy files in storage', async () => {
    const tempDir = path.resolve(process.cwd(), 'storage/temp');
    const legacyData = Buffer.from('LEGACY_UNENCRYPTED_FILE_CONTENT_2026', 'utf8');
    const legacyPath = path.join(tempDir, `legacy_test_${Date.now()}.txt`);
    fs.writeFileSync(legacyPath, legacyData);

    const decrypted = await StorageService.readDecryptedFile(legacyPath);
    expect(decrypted.equals(legacyData)).toBe(true);

    fs.unlinkSync(legacyPath);
  });

  it('DR-04: Full snapshot engine bundles database, blobs, and HMAC-signed manifest', async () => {
    const backup = await BackupService.createFullBackup();

    expect(backup.backupId).toBeDefined();
    expect(backup.backupPath).toBeDefined();
    expect(backup.manifest).toBeDefined();
    expect(backup.manifest.manifestHmac).toBeDefined();
    expect(backup.manifest.manifestHmac.length).toBe(64);
    expect(backup.manifest.databaseStats.users).toBeGreaterThan(0);
    expect(backup.manifest.databaseStats.auditLogs).toBeGreaterThan(0);

    // Verify cryptographic integrity of archive
    const verification = await BackupService.verifyBackupArchive(backup.backupId);
    expect(verification.isValid).toBe(true);
    expect(verification.manifest.backupId).toBe(backup.backupId);
  });

  it('DR-05: Backup verification detects tampering or manifest manipulation', async () => {
    const backup = await BackupService.createFullBackup();
    const manifestPath = path.join(backup.backupPath, 'manifest.json');

    expect(fs.existsSync(manifestPath)).toBe(true);

    // Read manifest, tamper with a property, write back
    const rawManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    rawManifest.environment = 'TAMPERED_ENVIRONMENT_ATTACK';
    fs.writeFileSync(manifestPath, JSON.stringify(rawManifest, null, 2), 'utf8');

    // Verify tampering is caught
    const verification = await BackupService.verifyBackupArchive(backup.backupId);
    expect(verification.isValid).toBe(false);
    expect(verification.errors.length).toBeGreaterThan(0);
    expect(verification.errors[0]).toContain('HMAC signature mismatch');
  });

  it('DR-06: Admin API routes enforce RBAC and provide backup lifecycle operations', async () => {
    // 1. Unauthenticated request rejected
    const unauthRes = await request(app).get('/api/admin/backups');
    expect(unauthRes.status).toBe(401);

    // 2. Regular viewer user rejected with 403
    const viewerRes = await request(app)
      .get('/api/admin/backups')
      .set('Cookie', viewerCookie);
    expect(viewerRes.status).toBe(403);

    // 3. Admin can list backups
    const listRes = await request(app)
      .get('/api/admin/backups')
      .set('Cookie', adminCookie);
    expect(listRes.status).toBe(200);
    expect(Array.isArray(listRes.body.backups)).toBe(true);
    expect(listRes.body.backups.length).toBeGreaterThan(0);

    // 4. Admin can trigger fresh verified snapshot
    const createRes = await request(app)
      .post('/api/admin/backups')
      .set('Cookie', adminCookie);
    expect(createRes.status).toBe(201);
    expect(createRes.body.backupId).toBeDefined();
    const newBackupId = createRes.body.backupId;

    // 5. Admin can verify integrity of snapshot
    const verifyRes = await request(app)
      .post('/api/admin/backups/verify')
      .set('Cookie', adminCookie)
      .send({ backupId: newBackupId });
    expect(verifyRes.status).toBe(200);
    expect(verifyRes.body.isValid).toBe(true);
  });
});
