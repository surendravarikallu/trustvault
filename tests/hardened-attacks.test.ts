import request from 'supertest';
import { app } from '../src/server';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
import { StorageService } from '../src/services/storageService';
import { applyForensicWatermark, protectPdfWithPassword, encodeSteganographicPayload, MAX_JIT_PDF_SIZE_BYTES } from '../src/utils/pdfEngine';
import { getRequestContext } from '../src/controllers/documentController';
import { redisGet, redisSet, isRedisConnected } from '../src/utils/redis';
import jwt from 'jsonwebtoken';
import { config } from '../src/config';
import fs from 'fs';
import path from 'path';
import { PDFDocument } from 'pdf-lib';

describe('Hardened Attack Vectors Defense Suite (Threats T-48 to T-53)', () => {
  let ownerUser: any;
  let testDoc: any;
  let ownerToken: string;

  beforeAll(async () => {
    const ownerRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });

    if (ownerRes.status === 200) {
      ownerUser = ownerRes.body.user;
      ownerToken = ownerRes.body.token;
    } else {
      ownerUser = await prisma.user.upsert({
        where: { email: 'alice.hardened@trustvault.local' },
        update: {},
        create: {
          email: 'alice.hardened@trustvault.local',
          name: 'Alice Hardened',
          passwordHash: '$2b$10$abcdefghijklmnopqrstuvwxyzABCDEF',
          role: 'OWNER',
          tokenVersion: 1
        }
      });
      ownerToken = jwt.sign(
        { userId: ownerUser.id, tokenVersion: 1 },
        config.jwtSecret,
        { expiresIn: '1h', algorithm: 'HS256' }
      );
    }

    // Create a real valid PDF for tests
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([600, 400]);
    page.drawText('Confidential Hardened Vault Test Document');
    const pdfBytes = await pdfDoc.save();

    const tempDir = path.resolve('storage/temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
    const tempFilePath = path.join(tempDir, `test-${Date.now()}.pdf`);
    fs.writeFileSync(tempFilePath, Buffer.from(pdfBytes));

    const stored = await StorageService.persistFile(tempFilePath);
    if (fs.existsSync(tempFilePath)) fs.unlinkSync(tempFilePath);

    testDoc = await prisma.document.create({
      data: {
        title: 'Hardened Vault Asset',
        category: 'FINANCE',
        originalFilename: 'asset.pdf',
        storedFilename: stored.storedFilename,
        mimeType: 'application/pdf',
        fileSize: stored.fileSize,
        fileHash: stored.fileHash,
        ownerId: ownerUser.id
      }
    });
  });

  afterAll(async () => {
    await prisma.$disconnect();
  });

  // --- ATTACK 1 (T-48): CSRF on Cookie Sessions (CWE-352) ---
  describe('T-48: Cross-Site Request Forgery (CSRF) Mitigation', () => {
    it('CSRF-01: Rejects cookie-authenticated state-mutating request without X-TrustVault-Client header or valid origin', async () => {
      // Simulate cross-site POST initiated with victim session cookie from malicious-site.com
      const res = await request(app)
        .delete(`/api/documents/${testDoc.id}`)
        .set('Cookie', [`trustvault_token=${ownerToken}`])
        .set('Origin', 'https://malicious-attacker.com');

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/CSRF validation failed/i);
    });

    it('CSRF-02: Permits cookie-authenticated mutating request when X-TrustVault-Client: 1 header is provided', async () => {
      // Create a dummy document to delete
      const dummy = await prisma.document.create({
        data: {
          title: 'Dummy to delete',
          category: 'MISC',
          originalFilename: 'dummy.txt',
          storedFilename: 'non-existent',
          mimeType: 'text/plain',
          fileSize: 10,
          fileHash: 'fakehash',
          ownerId: ownerUser.id
        }
      });

      const res = await request(app)
        .delete(`/api/documents/${dummy.id}`)
        .set('Cookie', [`trustvault_token=${ownerToken}`])
        .set('X-TrustVault-Client', '1');

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/Document soft-deleted successfully/i);
    });

    it('CSRF-03: Allows API clients using Authorization: Bearer without cookie', async () => {
      const dummy2 = await prisma.document.create({
        data: {
          title: 'Dummy Bearer Test',
          category: 'MISC',
          originalFilename: 'dummy2.txt',
          storedFilename: 'non-existent',
          mimeType: 'text/plain',
          fileSize: 10,
          fileHash: 'fakehash2',
          ownerId: ownerUser.id
        }
      });

      const res = await request(app)
        .delete(`/api/documents/${dummy2.id}`)
        .set('Authorization', `Bearer ${ownerToken}`);

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/Document soft-deleted successfully/i);
    });
  });

  // --- ATTACK 2 (T-49): CPU Starvation / DoS via Heavy JIT PDF Transforms (CWE-400) ---
  describe('T-49: JIT PDF Resource Bounding & CPU Starvation Prevention', () => {
    it('DOS-PDF-01: Rejects dynamic watermarking on payloads exceeding 25MB threshold', async () => {
      const fakeHugeBuffer = Buffer.alloc(MAX_JIT_PDF_SIZE_BYTES + 1024); // 25MB + 1KB
      await expect(
        applyForensicWatermark(fakeHugeBuffer, { recipientEmail: 'eve@corp.com' })
      ).rejects.toThrow(/exceeds 25MB threshold/i);
    });

    it('DOS-PDF-02: Rejects PDF password encryption on payloads exceeding 25MB threshold', async () => {
      const fakeHugeBuffer = Buffer.alloc(MAX_JIT_PDF_SIZE_BYTES + 1024);
      await expect(
        protectPdfWithPassword(fakeHugeBuffer, 'Password123')
      ).rejects.toThrow(/exceeds 25MB threshold/i);
    });
  });

  // --- ATTACK 3 (T-50): Unauthenticated Redis Cache Store & Lateral Pivot (CWE-306) ---
  describe('T-50: Redis Authentication & Connection Security', () => {
    it('REDIS-01: Successfully connects to Redis using configured credentials and executes set/get', async () => {
      await redisSet('trustvault:security:test_key', 'secured_val', 10);
      const val = await redisGet('trustvault:security:test_key');
      expect(val).toBe('secured_val');
      expect(isRedisConnected()).toBe(true);
    });
  });

  // --- ATTACK 4 (T-51): Header-Based Client IP Spoofing & Audit Log Poisoning (CWE-290) ---
  describe('T-51: Reverse Proxy IP Header Spoofing Shield', () => {
    it('IP-SPOOF-01: Ignores cf-connecting-ip from non-loopback untrusted remote socket', () => {
      const mockReq: any = {
        socket: { remoteAddress: '203.0.113.50' }, // External Internet IP
        headers: {
          'cf-connecting-ip': '8.8.8.8', // Spoofed header
          'user-agent': 'Mozilla/5.0 Test'
        },
        ip: '203.0.113.50'
      };

      const ctx = getRequestContext(mockReq);
      // Must NOT trust the spoofed 8.8.8.8 header
      expect(ctx.ip).toBe('203.0.113.50');
    });

    it('IP-SPOOF-02: Rejects malformed or payload-injected IP headers even from loopback proxy', () => {
      const mockReq: any = {
        socket: { remoteAddress: '127.0.0.1' }, // Local reverse proxy
        headers: {
          'cf-connecting-ip': '1.2.3.4<script>alert(1)</script>', // Injected payload
          'user-agent': 'Safe UA'
        },
        ip: '127.0.0.1'
      };

      const ctx = getRequestContext(mockReq);
      // Must fall back to safe loopback IP and not reflect script payload
      expect(ctx.ip).toBe('127.0.0.1');
    });

    it('IP-SPOOF-03: Strips terminal control characters from User-Agent to prevent log forging', () => {
      const mockReq: any = {
        socket: { remoteAddress: '127.0.0.1' },
        headers: {
          'user-agent': 'NormalUA\x1b[31mInjectedRedText\x00'
        }
      };

      const ctx = getRequestContext(mockReq);
      expect(ctx.userAgent).not.toContain('\x1b');
      expect(ctx.userAgent).not.toContain('\x00');
    });
  });

  // --- ATTACK 5 (T-52): Static Master Key Exposure & Cryptographic Weak Derivation (CWE-326) ---
  describe('T-52: RFC 5869 HKDF Storage Key Derivation & Envelope Compatibility', () => {
    it('HKDF-01: Encrypts file using HKDF-derived key and verifies round-trip decryption', async () => {
      const plaintext = Buffer.from('Ultra-sensitive payroll records 2026');
      const tempPath = path.resolve('storage/temp/test-hkdf.txt');
      fs.writeFileSync(tempPath, plaintext);

      const persisted = await StorageService.persistFile(tempPath);
      if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);

      const filePath = StorageService.getSafeFilePath(persisted.storedFilename);
      expect(filePath).not.toBeNull();

      const decrypted = await StorageService.readDecryptedFile(filePath!);
      expect(decrypted.toString('utf-8')).toBe(plaintext.toString('utf-8'));

      await StorageService.deleteFile(persisted.storedFilename);
    });
  });

  // --- ATTACK 6 (T-53): Analog Hole, Display Scraping & Attribution Evasion (CWE-200 / CWE-592) ---
  describe('T-53: Steganographic Provenance & Watermark Metadata Embedding', () => {
    it('STEGO-01: Correctly encodes provenance string into zero-width characters', () => {
      const encoded = encodeSteganographicPayload('TV:user@trustvault.local');
      expect(encoded.length).toBeGreaterThan(0);
      // Must contain only zero-width space (\u200B) and zero-width non-joiner (\u200C)
      for (const char of encoded) {
        expect(['\u200B', '\u200C']).toContain(char);
      }
    });

    it('STEGO-02: Embeds recipient identity and hash into PDF metadata dictionary', async () => {
      const pdfDoc = await PDFDocument.create();
      const page = pdfDoc.addPage([500, 300]);
      page.drawText('Sample Provenance PDF');
      const rawBytes = await pdfDoc.save();

      const watermarked = await applyForensicWatermark(Buffer.from(rawBytes), {
        recipientEmail: 'whistleblower@external.org',
        ipAddress: '198.51.100.42',
        grantId: 'grant-test-1234'
      });

      const loaded = await PDFDocument.load(watermarked);
      expect(loaded.getTitle()).toContain('PROTECTED VAULT DOCUMENT');
      expect(loaded.getAuthor()).toContain('whistleblower@external.org');
      expect(loaded.getKeywords()).toContain('TRUSTVAULT_FORENSIC_TAG');
    });
  });
});
