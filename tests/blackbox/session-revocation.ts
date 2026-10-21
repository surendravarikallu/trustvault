/**
 * Blackbox Live Session Revocation Verification Suite
 * Tests persistent session revocation in database (Session table) across requests.
 * Driven by BASE_URL (defaults to http://127.0.0.1:7777).
 */

const BASE_URL = process.env.BASE_URL || 'http://127.0.0.1:7777';

interface LoginResponse {
  cookie: string;
  user: any;
}

async function loginUser(email: string, password: string): Promise<LoginResponse> {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Login failed for ${email} with status ${res.status}: ${text}`);
  }

  const setCookie = res.headers.get('set-cookie');
  if (!setCookie) {
    throw new Error(`No set-cookie header received for ${email}`);
  }

  const cookie = setCookie.split(';')[0];
  const data = await res.json();
  return { cookie, user: data.user };
}

async function requestMe(cookie: string): Promise<{ status: number; body: any }> {
  const res = await fetch(`${BASE_URL}/api/auth/me`, {
    headers: { Cookie: cookie }
  });
  let body: any;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  return { status: res.status, body };
}

async function logoutUser(cookie: string): Promise<{ status: number }> {
  const res = await fetch(`${BASE_URL}/api/auth/logout`, {
    method: 'POST',
    headers: { Cookie: cookie }
  });
  return { status: res.status };
}

export async function runSessionRevocationTest(): Promise<boolean> {
  console.log(`=======================================================`);
  console.log(` Blackbox Live Session Revocation Test`);
  console.log(` Target BASE_URL: ${BASE_URL}`);
  console.log(`=======================================================`);

  // Step 1: Login User A (Owner)
  console.log(`[1] Logging in User A (owner@trustvault.local)...`);
  const sessionA = await loginUser('owner@trustvault.local', 'Owner@TrustVault2026!');
  console.log(`    User A logged in. Cookie: ${sessionA.cookie.substring(0, 30)}...`);

  // Step 2: Login User B (Admin)
  console.log(`[2] Logging in User B (admin@trustvault.local)...`);
  const sessionB = await loginUser('admin@trustvault.local', 'Admin@TrustVault2026!');
  console.log(`    User B logged in. Cookie: ${sessionB.cookie.substring(0, 30)}...`);

  // Step 3: Verify both active sessions return 200
  console.log(`[3] Verifying active sessions before logout...`);
  const checkA1 = await requestMe(sessionA.cookie);
  const checkB1 = await requestMe(sessionB.cookie);
  if (checkA1.status !== 200 || checkB1.status !== 200) {
    throw new Error(`Session verification failed: User A status=${checkA1.status}, User B status=${checkB1.status}`);
  }
  console.log(`    User A: 200 OK (${checkA1.body.user.email})`);
  console.log(`    User B: 200 OK (${checkB1.body.user.email})`);

  // Step 4: Logout User A
  console.log(`[4] Logging out User A...`);
  const logoutRes = await logoutUser(sessionA.cookie);
  if (logoutRes.status !== 200) {
    throw new Error(`Logout failed for User A with status ${logoutRes.status}`);
  }
  console.log(`    User A logout returned 200 OK.`);

  // Step 5: Replay User A token against /api/auth/me (MUST return 401)
  console.log(`[5] Replaying User A session token after logout...`);
  const checkA2 = await requestMe(sessionA.cookie);
  console.log(`    User A replay status: ${checkA2.status} (Expected: 401)`);
  if (checkA2.status !== 401) {
    throw new Error(`CRITICAL SECURITY FAILURE: User A replayed session returned ${checkA2.status} instead of 401!`);
  }

  // Step 6: Verify User B session remains valid (MUST return 200)
  console.log(`[6] Verifying User B session isolation...`);
  const checkB2 = await requestMe(sessionB.cookie);
  console.log(`    User B status: ${checkB2.status} (Expected: 200)`);
  if (checkB2.status !== 200) {
    throw new Error(`Session cross-contamination: User B returned ${checkB2.status} instead of 200!`);
  }

  console.log(`-------------------------------------------------------`);
  console.log(` RESULT: PASS - Session revocation persisted in DB.`);
  console.log(` Revoked token instantly returns 401; isolated user remains 200.`);
  console.log(`=======================================================`);
  return true;
}

if (require.main === module) {
  runSessionRevocationTest()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('TEST FAILED:', err.message);
      process.exit(1);
    });
}
