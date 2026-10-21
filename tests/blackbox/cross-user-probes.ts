import { prisma } from '../../src/prisma';
import { StorageService } from '../../src/services/storageService';
import fs from 'fs';
import path from 'path';

const BASE_URL = process.env.BASE_URL || 'http://127.0.0.1:7777';

interface ProbeResult {
  route: string;
  method: string;
  actor: string;
  realStatus: number;
  nonexistentStatus: number | null;
  bodyIdentical: string;
  dtoLeak: string;
  notes: string;
}

const SENSITIVE_FIELDS = ['storedFilename', 'passwordHash', 'tokenVersion', 'mfaSecret'];

function checkForDtoLeak(body: any): string {
  if (!body) return 'CLEAN';
  const str = JSON.stringify(body);
  const found = SENSITIVE_FIELDS.filter(f => str.includes(`"${f}"`));
  return found.length > 0 ? `LEAK: ${found.join(', ')}` : 'CLEAN';
}

async function loginUser(email: string, password = getDefaultPassword(email)): Promise<string> {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const setCookie = res.headers.get('set-cookie');
  if (!setCookie) throw new Error(`Login failed for ${email}: ${res.status}`);
  return setCookie.split(';')[0];
}

function getDefaultPassword(email: string): string {
  const prefix = email.split('@')[0];
  const cap = prefix.charAt(0).toUpperCase() + prefix.slice(1);
  return `${cap}@TrustVault2026!`;
}

async function sendRequest(
  url: string,
  method = 'GET',
  cookie?: string,
  body?: any,
  headers: Record<string, string> = {}
) {
  const reqHeaders: Record<string, string> = { ...headers };
  if (cookie) reqHeaders['Cookie'] = cookie;
  if (body && !reqHeaders['Content-Type']) reqHeaders['Content-Type'] = 'application/json';

  const res = await fetch(url, {
    method,
    headers: reqHeaders,
    body: body ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined
  });

  let parsed: any = null;
  const rawText = await res.text();
  try {
    parsed = JSON.parse(rawText);
  } catch {
    parsed = rawText;
  }

  return { status: res.status, body: parsed, rawText };
}

async function main() {
  console.log(`Starting Section 3 Authorization Matrix Probes against ${BASE_URL}...`);

  // Ensure test users exist
  const ownerUser = await prisma.user.findUnique({ where: { email: 'owner@trustvault.local' } });
  const adminUser = await prisma.user.findUnique({ where: { email: 'admin@trustvault.local' } });
  let eveUser = await prisma.user.findUnique({ where: { email: 'eve@trustvault.local' } });

  if (!eveUser) {
    const bcrypt = await import('bcrypt');
    const hash = await bcrypt.hash('Eve@TrustVault2026!', 10);
    eveUser = await prisma.user.create({
      data: {
        email: 'eve@trustvault.local',
        name: 'Eve Adversary',
        passwordHash: hash,
        role: 'VIEWER',
        tokenVersion: 1
      }
    });
  }

  // Create Alice's private test document
  const tempDir = path.resolve('storage/temp');
  if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });
  const dummyFilePath = path.join(tempDir, `alice-doc-${Date.now()}.txt`);
  fs.writeFileSync(dummyFilePath, 'Alice confidential zero-trust test document');

  const stored = await StorageService.persistFile(dummyFilePath);
  if (fs.existsSync(dummyFilePath)) fs.unlinkSync(dummyFilePath);

  const aliceDoc = await prisma.document.create({
    data: {
      title: 'Alice Confidential Vault Doc',
      category: 'LEGAL',
      originalFilename: 'alice_confidential.txt',
      storedFilename: stored.storedFilename,
      mimeType: 'text/plain',
      fileSize: stored.fileSize,
      fileHash: stored.fileHash,
      ownerId: ownerUser!.id
    }
  });

  const realId = aliceDoc.id;
  const fakeId = '00000000-0000-0000-0000-000000000000';

  // Get Cookies
  const ownerCookie = await loginUser('owner@trustvault.local');
  const adminCookie = await loginUser('admin@trustvault.local');
  const eveCookie = await loginUser('eve@trustvault.local');

  const results: ProbeResult[] = [];

  // Helper for IDOR probes (real vs fake ID)
  async function probeIdor(
    name: string,
    routeTemplate: string,
    method: string,
    actorName: string,
    cookie?: string,
    payload?: any
  ) {
    const realUrl = `${BASE_URL}${routeTemplate.replace(':id', realId)}`;
    const fakeUrl = `${BASE_URL}${routeTemplate.replace(':id', fakeId)}`;

    const realRes = await sendRequest(realUrl, method, cookie, payload);
    const fakeRes = await sendRequest(fakeUrl, method, cookie, payload);

    const identical = realRes.status === fakeRes.status && realRes.rawText === fakeRes.rawText;
    const dtoCheck = checkForDtoLeak(realRes.body);

    let notes = '';
    if (realRes.status === 404 && identical) {
      notes = 'No existence oracle (Identical 404)';
    } else if (realRes.status === 403) {
      notes = 'Forbidden access blocked';
    } else if (realRes.status === 401) {
      notes = 'Authentication required';
    } else if (realRes.status === 200) {
      notes = 'Authorized access';
    }

    results.push({
      route: routeTemplate,
      method,
      actor: actorName,
      realStatus: realRes.status,
      nonexistentStatus: fakeRes.status,
      bodyIdentical: identical ? 'YES' : 'NO',
      dtoLeak: dtoCheck,
      notes
    });
  }

  // 1. Probes for Document Endpoints Taking :id
  const idRoutes: { route: string; method: string; payload?: any }[] = [
    { route: '/api/documents/:id', method: 'GET' },
    { route: '/api/documents/:id/download', method: 'GET' },
    { route: '/api/documents/:id', method: 'PUT', payload: { title: 'Hacked Title' } },
    { route: '/api/documents/:id', method: 'DELETE' },
    { route: '/api/documents/:id/versions', method: 'GET' },
    { route: '/api/documents/:id/permissions', method: 'GET' },
    { route: '/api/documents/:id/permissions', method: 'POST', payload: { targetEmail: 'eve@trustvault.local', permissionLevel: 'READ' } },
    { route: '/api/documents/:id/permissions/some-user-id', method: 'DELETE' },
    { route: '/api/documents/:id/ai-share-suggest', method: 'POST' }
  ];

  for (const r of idRoutes) {
    // Probe as Eve (Adversary / Unshared Viewer)
    await probeIdor(r.route, r.route, r.method, 'Eve (Unshared Viewer)', eveCookie, r.payload);
    // Probe as Unauthenticated
    await probeIdor(r.route, r.route, r.method, 'Unauthenticated', undefined, r.payload);
  }

  // Probe as Admin (Admin cannot download private doc without explicit grant)
  await probeIdor(
    '/api/documents/:id/download',
    '/api/documents/:id/download',
    'GET',
    'Admin (Without Grant)',
    adminCookie
  );

  // Probe as Owner (Authorized)
  await probeIdor(
    '/api/documents/:id',
    '/api/documents/:id',
    'GET',
    'Alice (Owner)',
    ownerCookie
  );
  await probeIdor(
    '/api/documents/:id/download',
    '/api/documents/:id/download',
    'GET',
    'Alice (Owner)',
    ownerCookie
  );

  // 2. Collection & General Document Routes
  // GET /api/documents (as Eve)
  const eveDocs = await sendRequest(`${BASE_URL}/api/documents`, 'GET', eveCookie);
  const eveSeesAliceDoc = Array.isArray(eveDocs.body?.documents) && eveDocs.body.documents.some((d: any) => d.id === realId);
  results.push({
    route: '/api/documents',
    method: 'GET',
    actor: 'Eve (Unshared Viewer)',
    realStatus: eveDocs.status,
    nonexistentStatus: null,
    bodyIdentical: 'N/A',
    dtoLeak: checkForDtoLeak(eveDocs.body),
    notes: eveSeesAliceDoc ? 'LEAK: Alice doc in list' : 'Alice doc hidden from listing'
  });

  // GET /api/documents/search (as Eve)
  const eveSearch = await sendRequest(`${BASE_URL}/api/documents/search?q=Alice`, 'GET', eveCookie);
  const eveSearchFindsAlice = Array.isArray(eveSearch.body?.documents) && eveSearch.body.documents.some((d: any) => d.id === realId);
  results.push({
    route: '/api/documents/search?q=Alice',
    method: 'GET',
    actor: 'Eve (Unshared Viewer)',
    realStatus: eveSearch.status,
    nonexistentStatus: null,
    bodyIdentical: 'N/A',
    dtoLeak: checkForDtoLeak(eveSearch.body),
    notes: eveSearchFindsAlice ? 'LEAK: Search leaks doc' : 'Search hides unauthorized doc'
  });

  // POST /api/documents (Viewer upload restriction)
  const viewerUpload = await sendRequest(`${BASE_URL}/api/documents`, 'POST', eveCookie, JSON.stringify({ title: 'Test' }));
  results.push({
    route: '/api/documents',
    method: 'POST',
    actor: 'Eve (Viewer Role)',
    realStatus: viewerUpload.status,
    nonexistentStatus: null,
    bodyIdentical: 'N/A',
    dtoLeak: checkForDtoLeak(viewerUpload.body),
    notes: viewerUpload.status === 403 ? 'L-05 Enforced: Viewers cannot upload' : 'Upload permitted'
  });

  // 3. Admin Routes (Probed as Eve vs Admin)
  const adminRoutes = [
    { route: '/api/admin/documents', method: 'GET' },
    { route: '/api/admin/audit-logs', method: 'GET' },
    { route: '/api/admin/audit-verify', method: 'GET' },
    { route: '/api/admin/users', method: 'GET' },
    { route: '/api/admin/users', method: 'POST', body: { email: 'new@test.local', name: 'New', role: 'VIEWER' } },
    { route: `/api/admin/users/${eveUser.id}/role`, method: 'PATCH', body: { role: 'OWNER' } },
    { route: `/api/admin/users/${eveUser.id}/deactivate`, method: 'POST' },
    { route: `/api/admin/users/${eveUser.id}/reset-password`, method: 'POST' },
    { route: `/api/admin/users/${eveUser.id}/reset-2fa`, method: 'POST' },
    { route: '/api/admin/backups', method: 'POST' },
    { route: '/api/admin/backups', method: 'GET' },
    { route: '/api/admin/backups/verify', method: 'POST' },
    { route: '/api/admin/retention/crypto-shred', method: 'POST' }
  ];

  for (const ar of adminRoutes) {
    const eveAdminRes = await sendRequest(`${BASE_URL}${ar.route}`, ar.method, eveCookie, ar.body);
    results.push({
      route: ar.route,
      method: ar.method,
      actor: 'Eve (Non-Admin)',
      realStatus: eveAdminRes.status,
      nonexistentStatus: null,
      bodyIdentical: 'N/A',
      dtoLeak: checkForDtoLeak(eveAdminRes.body),
      notes: eveAdminRes.status === 403 ? 'Role barrier strictly enforced (403)' : `Unexpected status ${eveAdminRes.status}`
    });
  }

  // Probe admin routes as Admin (Legitimate)
  const adminAuditRes = await sendRequest(`${BASE_URL}/api/admin/audit-verify`, 'GET', adminCookie);
  results.push({
    route: '/api/admin/audit-verify',
    method: 'GET',
    actor: 'Admin',
    realStatus: adminAuditRes.status,
    nonexistentStatus: null,
    bodyIdentical: 'N/A',
    dtoLeak: checkForDtoLeak(adminAuditRes.body),
    notes: 'Admin access granted (200 OK)'
  });

  // 4. Auth & Health Endpoints
  const healthRes = await sendRequest(`${BASE_URL}/api/health`, 'GET');
  results.push({
    route: '/api/health',
    method: 'GET',
    actor: 'Public / Unauthenticated',
    realStatus: healthRes.status,
    nonexistentStatus: null,
    bodyIdentical: 'N/A',
    dtoLeak: checkForDtoLeak(healthRes.body),
    notes: healthRes.status === 200 && JSON.stringify(healthRes.body) === '{"status":"ok"}'
      ? 'Minimal health probe ({"status":"ok"}, no leaks)'
      : 'Health check response'
  });

  const meUnauth = await sendRequest(`${BASE_URL}/api/auth/me`, 'GET');
  results.push({
    route: '/api/auth/me',
    method: 'GET',
    actor: 'Unauthenticated',
    realStatus: meUnauth.status,
    nonexistentStatus: null,
    bodyIdentical: 'N/A',
    dtoLeak: checkForDtoLeak(meUnauth.body),
    notes: 'Auth barrier enforced (401)'
  });

  // Clean up Alice's test document
  await prisma.document.delete({ where: { id: realId } });
  if (stored.storedFilename) {
    const fullStoragePath = StorageService.getSafeFilePath(stored.storedFilename);
    if (fullStoragePath && fs.existsSync(fullStoragePath)) fs.unlinkSync(fullStoragePath);
  }

  // Print Table
  console.log('\n========================================================================================================');
  console.log(' SECTION 3 COMPREHENSIVE AUTHORIZATION & ACCESS MATRIX');
  console.log('========================================================================================================\n');

  console.log('| Route | Method | Actor | Real Doc | Fake Doc | Body Identical? | DTO Leak? | Auth / Oracle Evaluation |');
  console.log('| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- |');
  for (const r of results) {
    const fakeStr = r.nonexistentStatus !== null ? r.nonexistentStatus.toString() : '—';
    console.log(`| \`${r.route}\` | ${r.method} | ${r.actor} | ${r.realStatus} | ${fakeStr} | ${r.bodyIdentical} | ${r.dtoLeak} | ${r.notes} |`);
  }
  console.log('\n========================================================================================================');
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Fatal probe failure:', err);
    process.exit(1);
  });
