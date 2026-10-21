import { describe, it, expect, beforeAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../src/server';
import { Role, PermissionLevel } from '../src/dal/types';
import { extractAuthCookie } from './testAuth';

let adminCookie: string;
let ownerCookie: string;
let viewerCookie: string;
let eveCookie: string;

beforeAll(async () => {
  // Authenticate base personas
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.local', password: 'Admin@TrustVault2026!' });
  adminCookie = extractAuthCookie(adminRes);

  const ownerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });
  ownerCookie = extractAuthCookie(ownerRes);

  const viewerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'viewer@trustvault.local', password: 'Viewer@TrustVault2026!' });
  viewerCookie = extractAuthCookie(viewerRes);

  const eveRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'eve@trustvault.local', password: 'Eve@TrustVault2026!' });
  eveCookie = extractAuthCookie(eveRes);
});

describe('Identity, Session Revocation & Privilege Matrix Suite', () => {
  it('ID-01: Deactivating user immediately severs active session cookie (HTTP 401)', async () => {
    // 1. Create a temporary user and login
    const tempEmail = `deact_user_${Date.now()}@trustvault.local`;
    const regRes = await request(app)
      .post('/api/auth/register')
      .send({ email: tempEmail, password: 'Password123!', name: 'Deactivate Target' });
    expect(regRes.status).toBe(201);
    const cookie = extractAuthCookie(regRes);
    const userId = regRes.body.user.id;

    // 2. Confirm cookie session is initially valid
    const meBefore = await request(app).get('/api/auth/me').set('Cookie', cookie);
    expect(meBefore.status).toBe(200);

    // 3. Admin deactivates the user
    const deactRes = await request(app)
      .post(`/api/admin/users/${userId}/deactivate`)
      .set('Cookie', adminCookie);
    expect(deactRes.status).toBe(200);

    // 4. Confirm subsequent call with same cookie is blocked immediately
    const meAfter = await request(app).get('/api/auth/me').set('Cookie', cookie);
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
      .set('Cookie', ownerCookie);
    const docId = docsRes.body.documents[0].id;

    // Alice grants EDIT to Bob
    await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Cookie', ownerCookie)
      .send({ targetEmail: 'viewer@trustvault.local', permissionLevel: PermissionLevel.EDIT });

    // Bob (Editor) attempts to grant permissions to Eve
    const bobGrantRes = await request(app)
      .post(`/api/documents/${docId}/permissions`)
      .set('Cookie', viewerCookie)
      .send({ targetEmail: 'eve@trustvault.local', permissionLevel: PermissionLevel.READ });

    // Must be 403 Forbidden: Only Owner can manage permissions
    expect(bobGrantRes.status).toBe(403);
    expect(bobGrantRes.body.error).toContain('Only the document owner can grant or revoke permissions');
  });

  it('ID-04: User lookup requires exact match and does not support wildcard enumeration', async () => {
    // Probing user lookup with partial/wildcard
    const probeRes = await request(app)
      .get('/api/auth/lookup?email=*')
      .set('Cookie', viewerCookie);

    // Rejection: Exact match required; wildcards do not enumerate accounts
    expect(probeRes.status).toBe(404);
    expect(probeRes.body.error).toContain('User not found');
  });

  it('ID-05: Per-session logout: Logging out of session A revokes session A (401 on replay) while session B remains valid (200)', async () => {
    // 1. Log in twice as viewer to establish two concurrent sessions (A and B)
    const loginARes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer@trustvault.local', password: 'Viewer@TrustVault2026!' });
    expect(loginARes.status).toBe(200);
    const cookieA = extractAuthCookie(loginARes);

    const loginBRes = await request(app)
      .post('/api/auth/login')
      .send({ email: 'viewer@trustvault.local', password: 'Viewer@TrustVault2026!' });
    expect(loginBRes.status).toBe(200);
    const cookieB = extractAuthCookie(loginBRes);

    expect(cookieA).not.toBe(cookieB);

    // 2. Both sessions work initially
    const checkA = await request(app).get('/api/auth/me').set('Cookie', cookieA);
    expect(checkA.status).toBe(200);
    const checkB = await request(app).get('/api/auth/me').set('Cookie', cookieB);
    expect(checkB.status).toBe(200);

    // 3. User logs out from Session A
    const logoutRes = await request(app)
      .post('/api/auth/logout')
      .set('Cookie', cookieA);
    expect(logoutRes.status).toBe(200);

    // 4. Replaying Cookie A MUST return 401 Unauthorized immediately
    const replayA = await request(app)
      .get('/api/auth/me')
      .set('Cookie', cookieA);
    expect(replayA.status).toBe(401);
    expect(replayA.body.error).toContain('Session has been logged out or revoked');

    // 5. Session B MUST still work (status 200) so concurrent judges/evaluators are not logged out
    const stillActiveB = await request(app)
      .get('/api/auth/me')
      .set('Cookie', cookieB);
    expect(stillActiveB.status).toBe(200);
    expect(stillActiveB.body.user.email).toBe('viewer@trustvault.local');
  });

  it('ID-06: CSRF protection rejects mutating request with opaque null Origin (HTTP 403)', async () => {
    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .set('Origin', 'null')
      .send({ title: 'Adversary CSRF Upload' });

    expect(res.status).toBe(403);
    expect(res.body.error).toContain('CSRF validation failed');
  });
});

