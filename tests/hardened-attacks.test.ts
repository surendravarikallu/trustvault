import request from 'supertest';
import { app } from '../src/server';
import { prisma } from '../src/prisma';
import { StorageService } from '../src/services/storageService';
import { applyForensicWatermark, protectPdfWithPassword, encodeSteganographicPayload, MAX_JIT_PDF_SIZE_BYTES } from '../src/utils/pdfEngine';
import { getRequestContext } from '../src/controllers/documentController';
import { redisGet, redisSet, isRedisConnected } from '../src/utils/redis';
import jwt from 'jsonwebtoken';
import { config } from '../src/config';
import fs from 'fs';
import path from 'path';
import { PDFDocument } from 'pdf-lib';
import { extractAuthCookie } from './testAuth';
import { createSession } from '../src/dal/sessionDal';

describe('Hardened Attack Vectors Defense Suite (Threats T-48 to T-53)', () => {
  let ownerUser: any;
  let testDoc: any;
  let ownerCookie: string;
  let rawSetCookie: string;

  beforeAll(async () => {
    const ownerRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });

    if (ownerRes.status === 200) {
      ownerUser = ownerRes.body.user;
      rawSetCookie = Array.isArray(ownerRes.headers['set-cookie'])
        ? ownerRes.headers['set-cookie'][0]
        : ownerRes.headers['set-cookie'];
      ownerCookie = rawSetCookie.split(';')[0];
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
      const sessionId = await createSession(ownerUser.id);
      const token = jwt.sign(
        { userId: ownerUser.id, sessionId, tokenVersion: 1 },
        config.jwtSecret,
        { expiresIn: '1h', algorithm: 'HS256' }
      );
      ownerCookie = `__Host-trustvault_token=${token}`;
      rawSetCookie = `__Host-trustvault_token=${token}; Path=/; HttpOnly; Secure; SameSite=Lax`;
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
    if (testDoc?.id) {
      await prisma.documentPermission.deleteMany({ where: { documentId: testDoc.id } });
      await prisma.document.deleteMany({ where: { id: testDoc.id } });
    }
    await prisma.$disconnect();
  });

  // --- SINGLE CREDENTIAL PATH & COOKIE HARDENING ---
  describe('Single Credential Path & __Host- Cookie Isolation', () => {
    it('AUTH-CK-01: Login response body contains NO token field (zero JS token exposure)', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });

      expect(res.status).toBe(200);
      expect(res.body.token).toBeUndefined();
      expect(res.body.user).toBeDefined();
    });

    it('AUTH-CK-02: Exactly one cookie is set: __Host-trustvault_token with HttpOnly, Secure, Path=/, and NO Domain attribute', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });

      const cookies = res.headers['set-cookie'];
      expect(cookies).toBeDefined();
      expect(Array.isArray(cookies) ? cookies.length : 1).toBe(1);

      const cookieHeader = Array.isArray(cookies) ? cookies[0] : cookies;
      expect(cookieHeader).toContain('__Host-trustvault_token=');
      expect(cookieHeader).not.toContain('trustvault_token=s:'); // Legacy plain cookie must be absent
      expect(cookieHeader.toLowerCase()).toContain('httponly');
      expect(cookieHeader.toLowerCase()).toContain('secure');
      expect(cookieHeader.toLowerCase()).toContain('samesite=lax');
      expect(cookieHeader).toContain('Path=/');
      // __Host- cookies MUST NOT specify a Domain attribute
      expect(cookieHeader.toLowerCase()).not.toContain('domain=');
    });

    it('AUTH-CK-03: Rejects requests using Authorization: Bearer fallback (only __Host- cookie accepted)', async () => {
      // Craft a valid JWT token
      const token = jwt.sign(
        { userId: ownerUser.id, tokenVersion: 1 },
        config.jwtSecret,
        { expiresIn: '1h', algorithm: 'HS256' }
      );

      const res = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(res.status).toBe(401);
      expect(res.body.error).toContain('Missing secure __Host- session cookie');
    });

    it('AUTH-CK-04: Rejects requests providing only the legacy insecure trustvault_token cookie', async () => {
      const token = jwt.sign(
        { userId: ownerUser.id, tokenVersion: 1 },
        config.jwtSecret,
        { expiresIn: '1h', algorithm: 'HS256' }
      );

      const res = await request(app)
        .get('/api/auth/me')
        .set('Cookie', `trustvault_token=${token}`);

      expect(res.status).toBe(401);
      expect(res.body.error).toContain('Missing secure __Host- session cookie');
    });
  });

  // --- ATTACK 1 (T-48): CSRF on Cookie Sessions (CWE-352) ---
  describe('T-48: Cross-Site Request Forgery (CSRF) & Origin Validation', () => {
    it('CSRF-01: Rejects cross-origin state-mutating POST/DELETE with Origin: https://evil.example with 403 and zero mutation', async () => {
      const docCountBefore = await prisma.document.count();

      const res = await request(app)
        .delete(`/api/documents/${testDoc.id}`)
        .set('Cookie', ownerCookie)
        .set('Origin', 'https://evil.example');

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/CSRF validation failed: Cross-origin request rejected/i);

      // Verify zero state change: document was NOT deleted
      const docCountAfter = await prisma.document.count();
      expect(docCountAfter).toBe(docCountBefore);
    });

    it('CSRF-02: Permits same-origin or localhost mutating requests', async () => {
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
        .set('Cookie', ownerCookie)
        .set('Origin', 'http://127.0.0.1:7777')
        .set('Host', '127.0.0.1:7777');

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/Document soft-deleted successfully/i);
    });
  });

  // --- CORS & CSP HARDENING ---
  describe('CORS Removal & Pinned CSP Directives', () => {
    it('CORS-01: Access-Control-Allow-Origin is absent even when Origin: https://evil.example is passed', async () => {
      const res = await request(app)
        .get('/api/auth/me')
        .set('Origin', 'https://evil.example');

      expect(res.headers['access-control-allow-origin']).toBeUndefined();
      expect(res.headers['access-control-allow-credentials']).toBeUndefined();
    });

    it('CSP-01: CSP header strictly enforces pinned sources with no generic https: in style-src or font-src', async () => {
      const res = await request(app).get('/api/health');
      const csp = res.headers['content-security-policy'];

      expect(csp).toBeDefined();
      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("object-src 'none'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).toContain("script-src-attr 'none'");
      expect(csp).toContain("base-uri 'self'");

      // Verify pinned font-src and style-src without open https: wildcard
      const directives = csp.split(';').map((d: string) => d.trim());
      const styleDirective = directives.find((d: string) => d.startsWith('style-src '));
      const fontDirective = directives.find((d: string) => d.startsWith('font-src '));

      expect(styleDirective).toBeDefined();
      expect(styleDirective).not.toMatch(/https:(?!\/\/)/); // No open `https:` scheme
      expect(fontDirective).toBeDefined();
      expect(fontDirective).not.toMatch(/https:(?!\/\/)/);
      expect(csp).not.toContain('cloudflareinsights.com');
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
        socket: { remoteAddress: '203.0.113.50' },
        headers: {
          'cf-connecting-ip': '8.8.8.8',
          'user-agent': 'Mozilla/5.0 Test'
        },
        ip: '203.0.113.50'
      };

      const ctx = getRequestContext(mockReq);
      expect(ctx.ip).toBe('203.0.113.50');
    });

    it('IP-SPOOF-02: Rejects malformed or payload-injected IP headers even from loopback proxy', () => {
      const mockReq: any = {
        socket: { remoteAddress: '127.0.0.1' },
        headers: {
          'cf-connecting-ip': '1.2.3.4<script>alert(1)</script>',
          'user-agent': 'Safe UA'
        },
        ip: '127.0.0.1'
      };

      const ctx = getRequestContext(mockReq);
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

  // --- DOWNLOAD SECURITY & PREVIEW DEPLOYMENT RESTRICTION ---
  describe('Download Security & Preview Elimination', () => {
    it('HDR-02: Document download response strictly asserts X-Content-Type-Options: nosniff', async () => {
      const res = await request(app)
        .get(`/api/documents/${testDoc.id}/download`)
        .set('Cookie', ownerCookie);

      expect(res.status).toBe(200);
      expect(res.headers['x-content-type-options']).toBe('nosniff');
    });

    it('PRV-01: ?preview=true behaves identically to plain download (attachment header, octet-stream)', async () => {
      const res = await request(app)
        .get(`/api/documents/${testDoc.id}/download?preview=true`)
        .set('Cookie', ownerCookie);

      expect(res.status).toBe(200);
      // Strictly download-only model: Never inline
      expect(res.headers['content-disposition']).toContain('attachment');
      expect(res.headers['content-type']).toContain('application/octet-stream');
    });

    it('AUD-PRV-01: Both ?preview=true and raw download return 404 to an unshared user and log ACCESS_DENIED', async () => {
      const stranger = await prisma.user.upsert({
        where: { email: 'stranger.audit@trustvault.local' },
        update: {},
        create: {
          email: 'stranger.audit@trustvault.local',
          name: 'Stranger Audit',
          passwordHash: '$2b$10$abcdefghijklmnopqrstuvwxyzABCDEF',
          role: 'VIEWER',
          tokenVersion: 1
        }
      });
      const strangerSessionId = await createSession(stranger.id);
      const strangerToken = jwt.sign(
        { userId: stranger.id, sessionId: strangerSessionId, tokenVersion: 1 },
        config.jwtSecret,
        { expiresIn: '1h', algorithm: 'HS256' }
      );
      const strangerCookie = `__Host-trustvault_token=${strangerToken}`;

      // Probe raw download
      const dlRes = await request(app)
        .get(`/api/documents/${testDoc.id}/download`)
        .set('Cookie', strangerCookie);
      expect(dlRes.status).toBe(404);

      // Probe preview parameter
      const prvRes = await request(app)
        .get(`/api/documents/${testDoc.id}/download?preview=true`)
        .set('Cookie', strangerCookie);
      expect(prvRes.status).toBe(404);

      // Verify audit rows were recorded for both probes
      const auditRows = await prisma.auditLog.findMany({
        where: {
          userId: stranger.id,
          documentId: testDoc.id,
          action: 'ACCESS_DENIED'
        }
      });

      expect(auditRows.length).toBeGreaterThanOrEqual(2);
    });
  });
});
