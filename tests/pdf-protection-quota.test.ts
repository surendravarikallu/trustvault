import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../src/server';
import { prisma } from '../src/prisma';
import { PDFDocument } from 'pdf-lib';
import { closeRedis } from '../src/utils/redis';
import { extractAuthCookie } from './testAuth';

describe('Dynamic PDF Protection, OTP & Bounded Multi-Download Suite', () => {
  let ownerCookie: string;
  let viewerCookie: string;
  let viewerUserId: string;
  let pdfDocId: string;

  beforeAll(async () => {
    // 1. Authenticate Owner
    const ownerRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });
    expect(ownerRes.status).toBe(200);
    ownerCookie = extractAuthCookie(ownerRes);

    // 2. Authenticate Viewer
    const viewerRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer@trustvault.local', password: 'Viewer@TrustVault2026!' });
    expect(viewerRes.status).toBe(200);
    viewerCookie = extractAuthCookie(viewerRes);
    viewerUserId = viewerRes.body.user.id;

    // 3. Create a test PDF document
    const pdfDoc = await PDFDocument.create();
    const page = pdfDoc.addPage([400, 400]);
    page.drawText('CONFIDENTIAL TRUSTVAULT ASSET');
    const pdfBytes = await pdfDoc.save();

    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .attach('file', Buffer.from(pdfBytes), 'secret_board_minutes.pdf')
      .field('title', 'Secret Board Minutes')
      .field('category', 'BOARD_MEMO');

    expect(uploadRes.status).toBe(201);
    pdfDocId = uploadRes.body.document.id;
  });

  afterAll(async () => {
    if (pdfDocId) {
      await prisma.documentPermission.deleteMany({ where: { documentId: pdfDocId } });
      await prisma.document.deleteMany({ where: { id: pdfDocId } });
    }
    await prisma.$disconnect();
    await closeRedis();
  });

  it('QUOTA-01: Bounded Multi-Download Quota allows exactly N downloads and burns on Nth download', async () => {
    // 1. Owner grants READ permission with maxDownloads = 2
    const grantRes = await request(app)
      .post(`/api/documents/${pdfDocId}/permissions`)
      .set('Cookie', ownerCookie)
      .send({
        targetEmail: 'viewer@trustvault.local',
        permissionLevel: 'READ',
        maxDownloads: 2,
        burnOnDownload: false
      });
    expect(grantRes.status).toBe(201);

    // 2. Download 1 (Remaining: 1) -> HTTP 200
    const dl1 = await request(app)
      .get(`/api/documents/${pdfDocId}/download`)
      .set('Cookie', viewerCookie);
    expect(dl1.status).toBe(200);

    // Give brief delay for res.on('finish') async database update
    await new Promise((r) => setTimeout(r, 100));

    // Verify DB count is now 1
    const permAfter1 = await prisma.documentPermission.findUnique({
      where: { documentId_userId: { documentId: pdfDocId, userId: viewerUserId } }
    });
    expect(permAfter1).not.toBeNull();
    expect(permAfter1?.downloadCount).toBe(1);

    // 3. Download 2 (Second of 2 allowed) -> HTTP 200
    const dl2 = await request(app)
      .get(`/api/documents/${pdfDocId}/download`)
      .set('Cookie', viewerCookie);
    expect(dl2.status).toBe(200);

    // Give brief delay for res.on('finish') quota exhaustion auto-burn
    await new Promise((r) => setTimeout(r, 150));

    // 4. Download 3 (Exceeded quota of 2) -> HTTP 404 (Fail-closed)
    const dl3 = await request(app)
      .get(`/api/documents/${pdfDocId}/download`)
      .set('Cookie', viewerCookie);
    expect(dl3.status).toBe(404);
  });

  it('PDF-OTP-01: Document with PDF Protection requires valid OTP to download and decrypt', async () => {
    // 1. Owner grants READ with PDF protection and custom OTP
    const testOtp = 'VAULT99X';
    const grantRes = await request(app)
      .post(`/api/documents/${pdfDocId}/permissions`)
      .set('Cookie', ownerCookie)
      .send({
        targetEmail: 'viewer@trustvault.local',
        permissionLevel: 'READ',
        maxDownloads: 5,
        pdfProtected: true,
        otp: testOtp,
        watermarkText: 'TOP SECRET LEGAL DISCLOSURE'
      });

    expect(grantRes.status).toBe(201);
    expect(grantRes.body.otp).toBe(testOtp);

    // 2. Viewer attempts download without OTP -> HTTP 401
    const noOtpRes = await request(app)
      .get(`/api/documents/${pdfDocId}/download`)
      .set('Cookie', viewerCookie);

    expect(noOtpRes.status).toBe(401);
    expect(noOtpRes.body.pdfProtected).toBe(true);

    // 3. Viewer attempts download with invalid OTP -> HTTP 401
    const wrongOtpRes = await request(app)
      .get(`/api/documents/${pdfDocId}/download`)
      .set('Cookie', viewerCookie)
      .set('x-pdf-otp', 'WRONG_CODE');

    expect(wrongOtpRes.status).toBe(401);
    expect(wrongOtpRes.body.error).toContain('Invalid OTP');

    // 4. Viewer downloads with valid OTP -> HTTP 200 & returns encrypted PDF
    const validOtpRes = await request(app)
      .get(`/api/documents/${pdfDocId}/download`)
      .set('Cookie', viewerCookie)
      .set('x-pdf-otp', testOtp)
      .buffer(true)
      .parse((res, callback) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(Buffer.from(c)));
        res.on('end', () => callback(null, Buffer.concat(chunks)));
      });

    expect(validOtpRes.status).toBe(200);
    expect(validOtpRes.headers['content-disposition']).toContain('attachment');
    expect(validOtpRes.body).toBeDefined();

    // Verify downloaded bytes are encrypted (cannot be read without ignoreEncryption)
    const downloadedBytes = validOtpRes.body as Buffer;
    let isEncrypted = false;
    try {
      await PDFDocument.load(downloadedBytes);
    } catch (err: any) {
      if (err.message && err.message.includes('encrypted')) {
        isEncrypted = true;
      }
    }
    expect(isEncrypted).toBe(true);
  });

  it('COOKIE-01: HttpOnly cookie allows seamless authentication without Bearer header', async () => {
    // 1. Login user and extract cookie
    const loginRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });

    expect(loginRes.status).toBe(200);
    expect(loginRes.body.token).toBeUndefined(); // Zero token in body
    const cookie = extractAuthCookie(loginRes);

    // 2. Access /api/auth/me using ONLY the cookie (no Authorization header)
    const meRes = await request(app)
      .get('/api/auth/me')
      .set('Cookie', cookie);

    expect(meRes.status).toBe(200);
    expect(meRes.body.user.email).toBe('owner@trustvault.local');

    // 3. Logout clears cookie
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', cookie);

    expect(logoutRes.status).toBe(200);
    const logoutCookies = logoutRes.headers['set-cookie'];
    expect(logoutCookies).toBeDefined();
  });
});
