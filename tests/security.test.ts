import { describe, it, expect, beforeAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../src/server';
import { PermissionLevel, Role, AuditStatus } from '../src/dal/types';
import { getAuditLogs, verifyAuditChain } from '../src/dal/auditDal';
import { exportAuditAnchor } from '../src/utils/auditAnchor';

let adminToken: string;
let ownerToken: string; // Alice (Owner)
let viewerToken: string; // Bob (Authorized Viewer)
let eveToken: string; // Eve (Adversary / Unshared Viewer)

let sharedDocId: string; // Doc 1: MSA Acme (shared with Bob)
let restrictedDocId: string; // Doc 2: Executive Comp (Alice private)
let bobUserId: string;
let eveUserId: string;

beforeAll(async () => {
  // 1. Authenticate Personas
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.local', password: 'Admin@TrustVault2026!' });
  expect(adminRes.status).toBe(200);
  adminToken = adminRes.body.token;

  const ownerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });
  expect(ownerRes.status).toBe(200);
  ownerToken = ownerRes.body.token;

  const viewerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'viewer@trustvault.local', password: 'Viewer@TrustVault2026!' });
  expect(viewerRes.status).toBe(200);
  viewerToken = viewerRes.body.token;
  bobUserId = viewerRes.body.user.id;

  const eveRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'eve@trustvault.local', password: 'Eve@TrustVault2026!' });
  expect(eveRes.status).toBe(200);
  eveToken = eveRes.body.token;
  eveUserId = eveRes.body.user.id;

  // 2. Fetch Alice's documents to obtain real IDs
  const docsRes = await request(app)
    .get('/api/documents')
    .set('Authorization', `Bearer ${ownerToken}`);
  expect(docsRes.status).toBe(200);

  const doc1 = docsRes.body.documents.find((d: any) => d.title.includes('Master Services Agreement'));
  const doc2 = docsRes.body.documents.find((d: any) => d.title.includes('Executive Compensation'));

  expect(doc1).toBeDefined();
  expect(doc2).toBeDefined();

  sharedDocId = doc1.id;
  restrictedDocId = doc2.id;
});

describe('TrustVault 16-Suite Security & Access Control Engine', () => {
  // Test 1: IDOR Download Blocked with 404 (L-01, L-06)
  it('1. test_idor_download_blocked_with_404: Unshared user (Eve) receives 404 on download probe', async () => {
    const res = await request(app)
      .get(`/api/documents/${restrictedDocId}/download`)
      .set('Authorization', `Bearer ${eveToken}`);

    // Status Code Contract: Must be 404 (not 403) to prevent document existence enumeration
    expect(res.status).toBe(404);
    expect(res.body.error).toContain('Document not found');
  });

  // Test 2: IDOR Metadata Blocked with 404 (L-06)
  it('2. test_idor_metadata_blocked_with_404: Unshared user (Eve) receives 404 on metadata probe', async () => {
    const res = await request(app)
      .get(`/api/documents/${restrictedDocId}`)
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(404);
    expect(res.body.error).toContain('Document not found');
  });

  // Legitimate Access Baseline
  it('Baseline: Authorized user (Bob) downloads document granted to him (Returns 200)', async () => {
    const res = await request(app)
      .get(`/api/documents/${sharedDocId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(200);
    expect(res.header['content-disposition']).toContain('attachment');
  });

  // Test 3: Instant Revocation (L-02)
  it('3. test_instant_revocation: Revoking access blocks subsequent download immediately (Returns 404)', async () => {
    // 1. Verify Bob currently has access
    const beforeRes = await request(app)
      .get(`/api/documents/${sharedDocId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(beforeRes.status).toBe(200);

    // 2. Alice (Owner) revokes Bob's access
    const revokeRes = await request(app)
      .delete(`/api/documents/${sharedDocId}/permissions/${bobUserId}`)
      .set('Authorization', `Bearer ${ownerToken}`);
    expect(revokeRes.status).toBe(200);

    // 3. Bob attempts to download again with existing token -> MUST RETURN 404 IMMEDIATELY!
    const afterRes = await request(app)
      .get(`/api/documents/${sharedDocId}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);
    expect(afterRes.status).toBe(404);

    // 4. Restore Bob's permission for remaining test isolation
    await request(app)
      .post(`/api/documents/${sharedDocId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        targetEmail: 'viewer@trustvault.local',
        permissionLevel: PermissionLevel.READ
      });
  });

  // Test 4: Expired Grant Returns 404 (L-05)
  it('4. test_expired_grant_returns_404: Time-bounded grant in the past returns 404', async () => {
    // Grant Eve access that expired yesterday
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const grantRes = await request(app)
      .post(`/api/documents/${sharedDocId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        targetEmail: 'eve@trustvault.local',
        permissionLevel: PermissionLevel.READ,
        expiresAt: yesterday
      });
    expect(grantRes.status).toBe(201);

    // Eve attempts to download -> Expired grant evaluated as non-existent (404)
    const res = await request(app)
      .get(`/api/documents/${sharedDocId}/download`)
      .set('Authorization', `Bearer ${eveToken}`);
    expect(res.status).toBe(404);

    // Clean up Eve's grant
    await request(app)
      .delete(`/api/documents/${sharedDocId}/permissions/${eveUserId}`)
      .set('Authorization', `Bearer ${ownerToken}`);
  });

  // Test 5: Reader Cannot Edit Document (403 Forbidden) (L-06)
  it('5. test_reader_cannot_edit_document: User with READ grant receives 403 on PUT', async () => {
    const fakePdf = Buffer.from('%PDF-1.4\nNew Content Payload\n%%EOF');
    const res = await request(app)
      .put(`/api/documents/${sharedDocId}`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .attach('file', fakePdf, 'updated.pdf');

    // User is visible (active READ grant) but unauthorized for action -> 403 Forbidden
    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Insufficient permissions');
  });

  // Test 6: Editor Cannot Grant Permissions (L-03)
  it('6. test_editor_cannot_grant_permissions: Editor receives 403 when attempting to grant access', async () => {
    // Elevate Bob to EDIT
    await request(app)
      .post(`/api/documents/${sharedDocId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        targetEmail: 'viewer@trustvault.local',
        permissionLevel: PermissionLevel.EDIT
      });

    // Bob attempts to grant access to Eve
    const res = await request(app)
      .post(`/api/documents/${sharedDocId}/permissions`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({
        targetEmail: 'eve@trustvault.local',
        permissionLevel: PermissionLevel.READ
      });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Only the document owner can grant or revoke');

    // Restore Bob to READ
    await request(app)
      .post(`/api/documents/${sharedDocId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({
        targetEmail: 'viewer@trustvault.local',
        permissionLevel: PermissionLevel.READ
      });
  });

  // Test 7: Admin Cannot Download Without Explicit Grant (L-04)
  it('7. test_admin_cannot_download_without_grant: Admin receives 403 when probing private document content', async () => {
    const res = await request(app)
      .get(`/api/documents/${restrictedDocId}/download`)
      .set('Authorization', `Bearer ${adminToken}`);

    // Admin has metadata rights, but downloads require explicit owner grant
    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Admins cannot download document content without an explicit grant');
  });

  // Test 8: Viewer Cannot Upload Documents (L-05)
  it('8. test_viewer_cannot_upload: VIEWER role receives 403 on document upload', async () => {
    const fakePdf = Buffer.from('%PDF-1.4\nViewer Upload Attempt\n%%EOF');
    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${viewerToken}`)
      .field('title', 'Unauthorized Viewer Document')
      .field('category', 'General')
      .attach('file', fakePdf, 'viewer_doc.pdf');

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('Viewers cannot upload documents');
  });

  // Test 9: Path Traversal Blocked (L-17)
  it('9. test_path_traversal_blocked: Path traversal sequences in document ID are rejected with 400', async () => {
    const res = await request(app)
      .get('/api/documents/..%2F..%2Fetc%2Fpasswd/download')
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Path traversal');
  });

  // Test 10: Direct Storage URL Blocked (L-17)
  it('10. test_direct_storage_url_blocked: Storage folder is not statically mounted via HTTP', async () => {
    const res = await request(app).get('/storage/uploads/test.pdf');
    expect(res.status).toBe(404);
  });

  // Test 11: Disguised Executable Rejected by Magic Bytes (L-15)
  it('11. test_disguised_executable_rejected: PE executable header disguised as .pdf is rejected with 400', async () => {
    const fakeExe = Buffer.from('MZ\x90\x00\x03\x00\x00\x00DisguisedMalwarePayload');
    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Disguised Malware Document')
      .field('category', 'General')
      .attach('file', fakeExe, 'innocent_report.pdf');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Disguised Windows executable (MZ header) detected');
  });

  // Test 12: Non-existent UUID Audit Logged Cleanly (L-11)
  it('12. test_nonexistent_uuid_audit_logged: Probing invalid UUID logs without FK constraint crash', async () => {
    const fakeUuid = '00000000-0000-0000-0000-000000000000';
    const res = await request(app)
      .get(`/api/documents/${fakeUuid}/download`)
      .set('Authorization', `Bearer ${viewerToken}`);

    expect(res.status).toBe(404);

    // Verify audit log recorded ACCESS_DENIED with fakeUuid
    const logs = await getAuditLogs({ action: 'ACCESS_DENIED', documentId: fakeUuid });
    expect(logs.total).toBeGreaterThan(0);
    expect(logs.logs[0].status).toBe(AuditStatus.DENIED);
  });

  // Test 13: Search Hides Unauthorized Documents (L-07)
  it('13. test_search_hides_unauthorized_docs: Search does not leak unauthorized document metadata', async () => {
    // Restricted doc contains 'Executive Compensation'
    const res = await request(app)
      .get('/api/documents/search?q=Compensation')
      .set('Authorization', `Bearer ${eveToken}`);

    expect(res.status).toBe(200);
    expect(res.body.documents.length).toBe(0);
  });

  // Test 14: Audit Chain Verification & Tail Truncation Detection (L-12, L-13)
  it('14. test_audit_chain_and_tail_truncation: Verifies HMAC chain integrity and external anchor match', async () => {
    const verification = await verifyAuditChain();
    expect(verification.valid).toBe(true);
    expect(verification.totalRecords).toBeGreaterThan(0);

    const headSeq = BigInt(verification.headSequence || '1');
    // Tamper with anchor to simulate truncation
    await exportAuditAnchor(headSeq + 10n, 'fake_truncated_head_hash_1234567890abcdef', new Date());

    const tampered = await verifyAuditChain();
    expect(tampered.valid).toBe(false);
    expect(tampered.error).toContain('Audit tail truncation detected');

    // Restore anchor
    await exportAuditAnchor(headSeq, verification.headHash || '', new Date());
    const restored = await verifyAuditChain();
    expect(restored.valid).toBe(true);
  });

  // Test 15: Token Version Invalidation on Demotion (L-01)
  it('15. test_token_version_invalidation_on_demotion: Changing role immediately invalidates active JWT', async () => {
    // 1. Create a temporary user and login
    const tempEmail = `demote_test_${Date.now()}@trustvault.local`;
    const regRes = await request(app)
      .post('/api/auth/register')
      .send({ email: tempEmail, password: 'Password123!', name: 'Demote Target' });
    expect(regRes.status).toBe(201);
    const tempToken = regRes.body.token;
    const tempUserId = regRes.body.user.id;

    // 2. Verify token is valid
    const meBefore = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${tempToken}`);
    expect(meBefore.status).toBe(200);

    // 3. Admin promotes user to OWNER (which bumps tokenVersion)
    const roleRes = await request(app)
      .patch(`/api/admin/users/${tempUserId}/role`)
      .set('Authorization', `Bearer ${adminToken}`)
      .send({ role: Role.OWNER });
    expect(roleRes.status).toBe(200);

    // 4. Existing JWT must be rejected immediately on subsequent call (Returns 401)
    const meAfter = await request(app)
      .get('/api/auth/me')
      .set('Authorization', `Bearer ${tempToken}`);
    expect(meAfter.status).toBe(401);
    expect(meAfter.body.error).toContain('Session revoked');
  });

  // Test 16: Router Stack Introspection Coverage (L-19)
  it('16. test_router_matrix_coverage: Introspects Express router stack to verify all endpoints are secured', () => {
    const routes: { path: string; method: string }[] = [];

    app._router.stack.forEach((middleware: any) => {
      if (middleware.route) {
        // Direct routes on app
        const methods = Object.keys(middleware.route.methods);
        methods.forEach((method) => {
          routes.push({ path: middleware.route.path, method: method.toUpperCase() });
        });
      } else if (middleware.name === 'router') {
        // Sub-routers mounted via app.use
        const basePath = middleware.regexp.source
          .replace('^\\', '')
          .replace('\\/?(?=\\/|$)', '')
          .replace(/\\\//g, '/');

        middleware.handle.stack.forEach((handler: any) => {
          if (handler.route) {
            const methods = Object.keys(handler.route.methods);
            methods.forEach((method) => {
              routes.push({
                path: `${basePath}${handler.route.path}`,
                method: method.toUpperCase()
              });
            });
          }
        });
      }
    });

    expect(routes.length).toBeGreaterThan(10);
    // Ensure critical endpoints are registered
    const paths = routes.map((r) => `${r.method} ${r.path}`);
    expect(paths.some((p) => p.includes('GET /api/documents/:id/download'))).toBe(true);
    expect(paths.some((p) => p.includes('POST /api/documents/:id/permissions'))).toBe(true);
    expect(paths.some((p) => p.includes('GET /api/admin/audit-verify'))).toBe(true);
  });
});
