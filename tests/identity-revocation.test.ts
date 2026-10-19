import { describe, it, expect, beforeAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../src/server';
import { Role, PermissionLevel } from '../src/dal/types';

let adminToken: string;
let ownerToken: string;
let viewerToken: string;
let eveToken: string;

beforeAll(async () => {
  // Authenticate base personas
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.local', password: 'Admin@TrustVault2026!' });
  adminToken = adminRes.body.token;

  const ownerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });
  ownerToken = ownerRes.body.token;

  const viewerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'viewer@trustvault.local', password: 'Viewer@TrustVault2026!' });
  viewerToken = viewerRes.body.token;

  const eveRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'eve@trustvault.local', password: 'Eve@TrustVault2026!' });
  eveToken = eveRes.body.token;
});

describe('Identity, Session Revocation & Privilege Matrix Suite', () => {
  it('ID-01: Deactivating user immediately severs active JWT session (HTTP 401)', async () => {
    // 1. Create a temporary user and login
    const tempEmail = `deact_user_${Date.now()}@trustvault.local`;
    const regRes = await request(app)
      .post('/api/auth/register')
      .send({ email: tempEmail, password: 'Password123!', name: 'Deactivate Target' });
    expect(regRes.status).toBe(201);
    const token = regRes.body.token;
    const userId = regRes.body.user.id;

    // 2. Confirm token is initially valid
    const meBefore = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(meBefore.status).toBe(200);

    // 3. Admin deactivates the user
    const deactRes = await request(app)
      .post(`/api/admin/users/${userId}/deactivate`)
      .set('Authorization', `Bearer ${adminToken}`);
    expect(deactRes.status).toBe(200);

    // 4. Confirm subsequent call with same token is blocked immediately
    const meAfter = await request(app).get('/api/auth/me').set('Authorization', `Bearer ${token}`);
    expect(meAfter.status).toBe(401);
    expect(meAfter.body.error).toContain('inactive');
  });

  it('ID-02: Non-existent email executes dummy bcrypt hash to resist timing attacks', async () => {
    // Time request with registered email but wrong password
    const t0 = Date.now();
    await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer@trustvault.local', password: 'WrongPassword2026!' });
    const realEmailDuration = Date.now() - t0;

    // Time request with non-existent email
    const t1 = Date.now();
    await request(app)
      .post('/api/auth/login')
      .send({ email: `nonexistent_${Date.now()}@trustvault.local`, password: 'WrongPassword2026!' });
    const fakeEmailDuration = Date.now() - t1;

    // Both must execute 12 bcrypt rounds (~50-300ms) rather than returning instantaneously (<5ms)
    expect(fakeEmailDuration).toBeGreaterThan(20);
    const diff = Math.abs(realEmailDuration - fakeEmailDuration);
    expect(diff).toBeLessThan(400);
  });

  it('ID-03: Editor with EDIT grant cannot delegate permissions to third parties (403)', async () => {
    // Fetch Alice's document
    const docsRes = await request(app)
      .get('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`);
    const docId = docsRes.body.documents[0].id;

    // Alice grants EDIT to Bob
    await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .send({ targetEmail: 'viewer@trustvault.local', permissionLevel: PermissionLevel.EDIT });

    // Bob (Editor) attempts to grant permissions to Eve
    const bobGrantRes = await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Authorization', `Bearer ${viewerToken}`)
      .send({ targetEmail: 'eve@trustvault.local', permissionLevel: PermissionLevel.READ });

    // Must be 403 Forbidden: Only Owner can manage permissions
    expect(bobGrantRes.status).toBe(403);
    expect(bobGrantRes.body.error).toContain('Only the document owner can grant or revoke permissions');
  });

  it('ID-04: User lookup requires exact match and does not support wildcard enumeration', async () => {
    // Probing user lookup with partial/wildcard
    const probeRes = await request(app)
      .get('/api/auth/lookup?email=*')
      .set('Authorization', `Bearer ${viewerToken}`);

    // Rejection: Exact match required; wildcards do not enumerate accounts
    expect(probeRes.status).toBe(404);
    expect(probeRes.body.error).toContain('User not found');
  });
});
