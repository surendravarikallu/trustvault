import { describe, it, expect, beforeAll } from 'vitest';
import request from 'supertest';
import { app } from '../src/server.js';
import { PrismaClient } from '@prisma/client';
import { verifyAuditChainIntegrity } from '../src/services/auditService.js';

const prisma = new PrismaClient();

let adminToken: string;
let aliceToken: string; // Document Owner
let bobToken: string;   // Authorized Viewer
let eveToken: string;   // Unauthorized Viewer / Intruder

let aliceDocId: string;
let restrictedDocId: string;
let bobUserId: string;

beforeAll(async () => {
  // Login each persona to retrieve authentic JWTs
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.com', password: 'AdminPassword123!' });
  adminToken = adminRes.body.token;

  const aliceRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'alice.owner@trustvault.com', password: 'OwnerPassword123!' });
  aliceToken = aliceRes.body.token;

  const bobRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'bob.viewer@trustvault.com', password: 'ViewerPassword123!' });
  bobToken = bobRes.body.token;
  bobUserId = bobRes.body.user.id;

  const eveRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'eve.intruder@trustvault.com', password: 'EvePassword123!' });
  eveToken = eveRes.body.token;

  // Retrieve Alice's documents
  const docsRes = await request(app)
    .get('/api/documents')
    .set('Authorization', `Bearer ${aliceToken}`);

  const doc1 = docsRes.body.documents.find((d: any) => d.title.includes('Master Service Agreement'));
  const doc2 = docsRes.body.documents.find((d: any) => d.title.includes('Executive Compensation'));

  aliceDocId = doc1.id;
  restrictedDocId = doc2.id;
});

describe('TrustVault Security & Access Control Suite', () => {
  // THREAT-01: IDOR
  it('THREAT-01: Blocks unauthorized user (Eve) from downloading Alice’s document (Returns 403)', async () => {
    const res = await request(app)
      .get(`/api/documents/${aliceDocId}/download`)
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Forbidden');
  });

  it('THREAT-01: Blocks unauthorized user (Eve) from accessing Alice’s document metadata (Returns 403)', async () => {
    const res = await request(app)
      .get(`/api/documents/${restrictedDocId}`)
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(403);
  });

  // Legitimate Access
  it('Allows authorized user (Bob) to download document when granted READ access (Returns 200)', async () => {
    const res = await request(app)
      .get(`/api/documents/${aliceDocId}/download`)
      .set('Authorization', `Bearer ${bobToken}`);

    expect(res.status).toBe(200);
    expect(res.header['content-disposition']).toContain('attachment');
  });

  // THREAT-02: Instant Revocation
  it('THREAT-02: Instantly revoking access stops authorized user on the next request (Returns 403)', async () => {
    // 1. Verify Bob currently has access
    const beforeRes = await request(app)
      .get(`/api/documents/${aliceDocId}/download`)
      .set('Authorization', `Bearer ${bobToken}`);
    expect(beforeRes.status).toBe(200);

    // 2. Alice revokes Bob's permission
    const revokeRes = await request(app)
      .delete(`/api/documents/${aliceDocId}/permissions/${bobUserId}`)
      .set('Authorization', `Bearer ${aliceToken}`);
    expect(revokeRes.status).toBe(200);

    // 3. Bob immediately attempts to download again -> Must be rejected immediately!
    const afterRes = await request(app)
      .get(`/api/documents/${aliceDocId}/download`)
      .set('Authorization', `Bearer ${bobToken}`);
    expect(afterRes.status).toBe(403);

    // 4. Restore Bob's permission for remaining test isolation
    await request(app)
      .post(`/api/documents/${aliceDocId}/permissions`)
      .set('Authorization', `Bearer ${aliceToken}`)
      .send({ targetEmail: 'bob.viewer@trustvault.com', permissionLevel: 'READ' });
  });

  // THREAT-05: Privilege Escalation
  it('THREAT-05: Prevents Viewer (Bob) from granting permissions to other users (Returns 403)', async () => {
    const res = await request(app)
      .post(`/api/documents/${aliceDocId}/permissions`)
      .set('Authorization', `Bearer ${bobToken}`)
      .send({ targetEmail: 'eve.intruder@trustvault.com', permissionLevel: 'EDIT' });

    expect(res.status).toBe(403);
  });

  it('THREAT-05: Prevents Viewer (Bob) from deleting Alice’s document (Returns 403)', async () => {
    const res = await request(app)
      .delete(`/api/documents/${aliceDocId}`)
      .set('Authorization', `Bearer ${bobToken}`);

    expect(res.status).toBe(403);
  });

  // THREAT-07: Search Metadata Isolation
  it('THREAT-07: Search does not leak unauthorized documents in results', async () => {
    // Restricted doc contains 'Executive Compensation'
    const res = await request(app)
      .get('/api/documents?q=Compensation')
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(200);
    expect(res.body.documents.length).toBe(0);
  });

  // THREAT-08: Denied Probes Are Audited
  it('THREAT-08: Records ACCESS_DENIED in the audit trail for failed access attempts', async () => {
    const deniedLogs = await prisma.auditLog.findMany({
      where: {
        status: 'DENIED',
        action: 'ACCESS_DENIED'
      }
    });

    expect(deniedLogs.length).toBeGreaterThan(0);
    const recent = deniedLogs[deniedLogs.length - 1];
    expect(recent.status).toBe('DENIED');
  });

  // THREAT-04: Cryptographic Hash Chain Integrity
  it('THREAT-04: Verifies cryptographic hash chain integrity of the audit ledger', async () => {
    const verification = await verifyAuditChainIntegrity();
    expect(verification.valid).toBe(true);
    expect(verification.totalRecords).toBeGreaterThan(0);
    expect(verification.headHash).toBeDefined();
  });

  // THREAT-06: Disguised File Upload Rejected
  it('THREAT-06: Rejects file upload with disguised executable bytes (Returns 400)', async () => {
    // Simulating an executable payload disguised with .pdf extension
    const fakePdf = Buffer.from('MZ\x90\x00\x03\x00\x00\x00BinaryExeHeaderPayload');

    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${aliceToken}`)
      .attach('file', fakePdf, 'malicious.pdf');

    expect(res.status).toBe(400);
  });
});
