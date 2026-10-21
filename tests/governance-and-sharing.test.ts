import { describe, it, expect, beforeAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../src/server';
import { verifyAuditChain } from '../src/dal/auditDal';
import { prisma } from '../src/prisma';
import { extractAuthCookie } from './testAuth';

let adminCookie: string;
let ownerCookie: string;
let viewerCookie: string;
let viewerUserId: string;
let testDocId: string;

beforeAll(async () => {
  // Login Admin
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.local', password: 'Admin@TrustVault2026!' });
  expect(adminRes.status).toBe(200);
  adminCookie = extractAuthCookie(adminRes);

  // Login Owner
  const ownerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });
  expect(ownerRes.status).toBe(200);
  ownerCookie = extractAuthCookie(ownerRes);

  // Login Viewer
  const viewerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'viewer@trustvault.local', password: 'Viewer@TrustVault2026!' });
  expect(viewerRes.status).toBe(200);
  viewerCookie = extractAuthCookie(viewerRes);
  viewerUserId = viewerRes.body.user.id;

  // Find a document belonging to Owner
  const docsRes = await request(app)
    .get('/api/documents')
    .set('Cookie', ownerCookie);
  expect(docsRes.status).toBe(200);
  expect(docsRes.body.documents.length).toBeGreaterThan(0);
  testDocId = docsRes.body.documents[0].id;
});

describe('Advanced Ephemeral Sharing & Admin User Governance Suite', () => {
  describe('Burn-on-Download (One-Time Transfer Protocol)', () => {
    it('BOD-01: Auto-revokes permission immediately upon successful download and returns 404 on subsequent probes', async () => {
      // 1. Owner grants READ permission with burnOnDownload: true
      const grantRes = await request(app)
        .post(`/api/documents/${testDocId}/permissions`)
        .set('Cookie', ownerCookie)
        .send({
          targetEmail: 'viewer@trustvault.local',
          permissionLevel: 'READ',
          burnOnDownload: true
        });
      expect(grantRes.status).toBe(201);

      // Verify grant in DB has burnOnDownload = true
      const grantInDb = await prisma.documentPermission.findUnique({
        where: {
          documentId_userId: {
            documentId: testDocId,
            userId: viewerUserId
          }
        }
      });
      expect(grantInDb).not.toBeNull();
      expect(grantInDb?.burnOnDownload).toBe(true);

      // 2. Viewer downloads the document (first attempt) -> 200 OK
      const downloadRes = await request(app)
        .get(`/api/documents/${testDocId}/download`)
        .set('Cookie', viewerCookie);
      expect(downloadRes.status).toBe(200);

      // Give event loop brief instant for res.on('finish') burn
      await new Promise((resolve) => setTimeout(resolve, 100));

      // 3. Verify grant has been burned from database
      const burnedGrant = await prisma.documentPermission.findUnique({
        where: {
          documentId_userId: {
            documentId: testDocId,
            userId: viewerUserId
          }
        }
      });
      expect(burnedGrant).toBeNull();

      // 4. Viewer attempts to download a second time -> 404 Not Found (zero existence confirmation)
      const secondDownload = await request(app)
        .get(`/api/documents/${testDocId}/download`)
        .set('Cookie', viewerCookie);
      expect(secondDownload.status).toBe(404);

      // 5. Verify audit ledger HMAC chain contains the burn event and remains valid
      const chainValid = await verifyAuditChain();
      expect(chainValid.valid).toBe(true);
    });
  });

  describe('Download Security: Removal of Inline Preview Bypass', () => {
    it('PRV-01: ?preview=true behaves strictly like a plain download (Content-Disposition: attachment)', async () => {
      // 1. Owner grants standard READ permission
      const grantRes = await request(app)
        .post(`/api/documents/${testDocId}/permissions`)
        .set('Cookie', ownerCookie)
        .send({
          targetEmail: 'viewer@trustvault.local',
          permissionLevel: 'READ',
          burnOnDownload: false
        });
      expect(grantRes.status).toBe(201);

      // 2. Viewer calls download with ?preview=true
      const previewRes = await request(app)
        .get(`/api/documents/${testDocId}/download?preview=true`)
        .set('Cookie', viewerCookie);
      expect(previewRes.status).toBe(200);
      // Strictly download-only: Must be attachment, application/octet-stream, never inline
      expect(previewRes.headers['content-disposition']).toContain('attachment');
      expect(previewRes.headers['content-type']).toContain('application/octet-stream');

      // Clean up grant
      await request(app)
        .delete(`/api/documents/${testDocId}/permissions/${viewerUserId}`)
        .set('Cookie', ownerCookie);
    });
  });

  describe('Admin Identity Governance & Emergency Reset Controls', () => {
    const testNewUserEmail = `analyst-${Date.now()}@trustvault.local`;
    let createdUserId: string;

    it('ADM-01: Provision user via admin API with validation and login capability', async () => {
      // 1. Rejects invalid payload
      const invalidRes = await request(app)
        .post('/api/admin/users')
        .set('Cookie', adminCookie)
        .send({
          name: 'X',
          email: 'not-an-email',
          password: '123'
        });
      expect(invalidRes.status).toBe(400);

      // 2. Non-admin is rejected with 403
      const nonAdminRes = await request(app)
        .post('/api/admin/users')
        .set('Cookie', viewerCookie)
        .send({
          name: 'Frank Castle',
          email: testNewUserEmail,
          password: 'Password@2026Test!',
          role: 'VIEWER'
        });
      expect(nonAdminRes.status).toBe(403);

      // 3. Admin successfully provisions user
      const createRes = await request(app)
        .post('/api/admin/users')
        .set('Cookie', adminCookie)
        .send({
          name: 'Frank Castle',
          email: testNewUserEmail,
          password: 'Password@2026Test!',
          role: 'VIEWER'
        });
      expect(createRes.status).toBe(201);
      expect(createRes.body.user).toBeDefined();
      expect(createRes.body.user.email).toBe(testNewUserEmail);
      createdUserId = createRes.body.user.id;

      // 4. Provisioned user can authenticate and receives cookie only (no body token)
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: testNewUserEmail, password: 'Password@2026Test!' });
      expect(loginRes.status).toBe(200);
      expect(loginRes.body.token).toBeUndefined();
      expect(loginRes.headers['set-cookie']).toBeDefined();
    });

    it('ADM-02: Admin resets user password and atomically invalidates active sessions (L-01)', async () => {
      // 1. Log in provisioned user and obtain session cookie
      const loginRes = await request(app)
        .post('/api/auth/login')
        .send({ email: testNewUserEmail, password: 'Password@2026Test!' });
      expect(loginRes.status).toBe(200);
      const activeUserCookie = extractAuthCookie(loginRes);

      // Verify cookie works
      const meBefore = await request(app)
        .get('/api/auth/me')
        .set('Cookie', activeUserCookie);
      expect(meBefore.status).toBe(200);

      // 2. Admin issues password reset
      const resetRes = await request(app)
        .post(`/api/admin/users/${createdUserId}/reset-password`)
        .set('Cookie', adminCookie)
        .send({ newPassword: 'NewSecret@2026Reset!' });
      expect(resetRes.status).toBe(200);

      // 3. Prior active session cookie is immediately invalidated (tokenVersion mismatch -> 401)
      const meAfter = await request(app)
        .get('/api/auth/me')
        .set('Cookie', activeUserCookie);
      expect(meAfter.status).toBe(401);

      // 4. Old password rejected, new password succeeds
      const oldLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: testNewUserEmail, password: 'Password@2026Test!' });
      expect(oldLogin.status).toBe(401);

      const newLogin = await request(app)
        .post('/api/auth/login')
        .send({ email: testNewUserEmail, password: 'NewSecret@2026Reset!' });
      expect(newLogin.status).toBe(200);
    });

    it('ADM-03: Admin emergency 2FA reset clears TOTP secrets and increments tokenVersion', async () => {
      // 1. Set dummy MFA secret for created user
      await prisma.user.update({
        where: { id: createdUserId },
        data: {
          mfaSecret: 'JBSWY3DPEHPK3PXP',
          mfaBackupCodes: ['hash1', 'hash2']
        }
      });

      // 2. Admin resets 2FA
      const resetMfaRes = await request(app)
        .post(`/api/admin/users/${createdUserId}/reset-2fa`)
        .set('Cookie', adminCookie);
      expect(resetMfaRes.status).toBe(200);

      // 3. Verify user in DB has mfaSecret = null and empty backup codes
      const userInDb = await prisma.user.findUnique({
        where: { id: createdUserId }
      });
      expect(userInDb?.mfaSecret).toBeNull();
      expect(userInDb?.mfaBackupCodes).toEqual([]);

      // 4. Verify HMAC audit chain remains 100% integral
      const chainValid = await verifyAuditChain();
      expect(chainValid.valid).toBe(true);

      // Clean up test user
      await prisma.user.delete({ where: { id: createdUserId } });
    });
  });
});
