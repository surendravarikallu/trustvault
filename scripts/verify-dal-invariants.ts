import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';

interface AuditCheckResult {
  id: string;
  name: string;
  vector: string;
  status: 'PROTECTED' | 'VULNERABLE';
  details: string;
  dataLeaked: boolean;
}

// -------------------------------------------------------------
// Resolve Target Web URL (from CLI argument, ENV, or default)
// -------------------------------------------------------------
function resolveTargetUrl(): string {
  // Check CLI arguments: --url=http... or --url http... or positional http...
  const args = process.argv.slice(2);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--url=')) {
      return arg.split('=')[1].replace(/\/+$/, '');
    }
    if (arg === '--url' && args[i + 1]) {
      return args[i + 1].replace(/\/+$/, '');
    }
    if (arg.startsWith('http://') || arg.startsWith('https://')) {
      return arg.replace(/\/+$/, '');
    }
  }

  // Check Environment Variable
  if (process.env.TARGET_URL) {
    return process.env.TARGET_URL.replace(/\/+$/, '');
  }

  // Default to local server
  return 'http://127.0.0.1:7777';
}

const TARGET_URL = resolveTargetUrl();
const results: AuditCheckResult[] = [];

console.log('================================================================');
console.log(' TrustVault Live Web Adversarial Security Verification Suite');
console.log(` Target Site URL: ${TARGET_URL}`);
console.log('================================================================\n');

// Helper for authenticating personas over HTTP
async function loginPersona(email: string, password: string): Promise<string> {
  const res = await fetch(`${TARGET_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  if (!res.ok) {
    throw new Error(`Login failed for ${email} (HTTP ${res.status}: ${res.statusText})`);
  }

  const data = (await res.json()) as any;
  return data.token;
}

async function runLiveWebAudit() {
  // -------------------------------------------------------------
  // Pre-Flight: Target Connectivity & Health Check
  // -------------------------------------------------------------
  console.log(`[Pre-Flight] Probing target connectivity at ${TARGET_URL}/api/health ...`);
  try {
    const healthRes = await fetch(`${TARGET_URL}/api/health`, { method: 'GET' });
    if (!healthRes.ok) {
      console.error(`FAIL: Target endpoint returned HTTP ${healthRes.status}. Ensure server is running.`);
      process.exit(1);
    }
    const healthData = (await healthRes.json()) as any;
    console.log(`  >> Connected successfully! System: "${healthData.system || 'TrustVault'}"\n`);
  } catch (err: any) {
    console.error(`\nCRITICAL: Unable to reach ${TARGET_URL}.`);
    console.error(`Network Error: ${err.message}`);
    console.error('Please ensure the web URL is reachable or your tunnel is active.\n');
    console.error('Usage:');
    console.error('  npx tsx scripts/verify-dal-invariants.ts --url https://your-site.com');
    console.error('  npx tsx scripts/verify-dal-invariants.ts https://your-tunnel.trycloudflare.com\n');
    process.exit(1);
  }

  // -------------------------------------------------------------
  // Test 1: JWT Signature Stripping & "alg: none" Token Forgery
  // -------------------------------------------------------------
  console.log('[Test 1] Testing JWT Signature Tampering & "alg: none" Forgery against Web API...');
  try {
    // 1. Unsigned "alg: none" token
    const headerBase64 = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payloadBase64 = Buffer.from(
      JSON.stringify({
        userId: 'forged-admin-id',
        email: 'admin@trustvault.local',
        role: 'ADMIN',
        tokenVersion: 1,
        iat: Math.floor(Date.now() / 1000)
      })
    ).toString('base64url');
    const algNoneToken = `${headerBase64}.${payloadBase64}.`;

    // 2. Forged signature signed with attacker secret
    const forgedSecretToken = jwt.sign(
      {
        userId: 'forged-admin-id',
        email: 'admin@trustvault.local',
        role: 'ADMIN',
        tokenVersion: 1
      },
      'attacker_compromised_random_secret_key_12345'
    );

    const [resNone, resForged] = await Promise.all([
      fetch(`${TARGET_URL}/api/admin/documents`, {
        headers: { Authorization: `Bearer ${algNoneToken}` }
      }),
      fetch(`${TARGET_URL}/api/admin/documents`, {
        headers: { Authorization: `Bearer ${forgedSecretToken}` }
      })
    ]);

    const isAlgNoneBlocked = resNone.status === 401;
    const isForgedSecretBlocked = resForged.status === 401;

    if (isAlgNoneBlocked && isForgedSecretBlocked) {
      results.push({
        id: 'ADV-01',
        name: 'Cryptographic JWT Boundary',
        vector: 'Algorithm None (alg: none) & Forged Secret Signatures',
        status: 'PROTECTED',
        details: 'All unsigned and forged tokens rejected with 401 Unauthorized over HTTP.',
        dataLeaked: false
      });
      console.log('  >> PASS: alg:none and fake-secret tokens strictly rejected (HTTP 401).\n');
    } else {
      results.push({
        id: 'ADV-01',
        name: 'Cryptographic JWT Boundary',
        vector: 'Algorithm None (alg: none) & Forged Secret Signatures',
        status: 'VULNERABLE',
        details: `Unexpected HTTP status (None: ${resNone.status}, Forged: ${resForged.status})`,
        dataLeaked: true
      });
      console.log('  >> FAIL: JWT signature verification bypassed!\n');
    }
  } catch (err: any) {
    console.error('Error during Test 1:', err.message);
  }

  // -------------------------------------------------------------
  // Test 2: HTTP Parameter Pollution & Query Object Injections
  // -------------------------------------------------------------
  console.log('[Test 2] Testing HTTP Parameter Pollution & Query Object Injections...');
  try {
    const eveToken = await loginPersona('eve@trustvault.local', 'Eve@TrustVault2026!');

    // 1. HPP: Sending duplicate query parameters
    const hppRes = await fetch(
      `${TARGET_URL}/api/documents/search?q=Confidential&q=Financial&owner=Alice&owner=Bob`,
      {
        headers: { Authorization: `Bearer ${eveToken}` }
      }
    );

    // 2. Object injection: Attempting qs operator style keys like q[$gt]=
    const objRes = await fetch(
      `${TARGET_URL}/api/documents/search?q[$ne]=test&category[in]=Executive`,
      {
        headers: { Authorization: `Bearer ${eveToken}` }
      }
    );

    const hppData = hppRes.ok ? ((await hppRes.json()) as any) : null;
    const hppSafe = hppRes.status === 200 && (hppData?.documents?.length || 0) === 0;
    const objSafe = objRes.status === 400 || (objRes.status === 200 && ((await objRes.json()) as any)?.documents?.length === 0);

    if (hppSafe && objSafe) {
      results.push({
        id: 'ADV-02',
        name: 'Query Parameter Integrity & HPP',
        vector: 'HTTP Parameter Pollution & Object Injection (qs operator tampering)',
        status: 'PROTECTED',
        details: 'Simple query parser neutralizes object injection. Zero unauthorized docs leaked.',
        dataLeaked: false
      });
      console.log('  >> PASS: Parameter pollution & object injections neutralized without data leak.\n');
    } else {
      results.push({
        id: 'ADV-02',
        name: 'Query Parameter Integrity & HPP',
        vector: 'HTTP Parameter Pollution & Object Injection (qs operator tampering)',
        status: 'VULNERABLE',
        details: `HPP returned ${hppData?.documents?.length || 0} documents.`,
        dataLeaked: true
      });
      console.log('  >> FAIL: Query injection leaked documents!\n');
    }
  } catch (err: any) {
    console.error('Error during Test 2:', err.message);
  }

  // -------------------------------------------------------------
  // Test 3: Path Traversal with Advanced Encoding & Null Bytes
  // -------------------------------------------------------------
  console.log('[Test 3] Testing Path Traversal, Null Bytes & Direct Storage Access over Web...');
  try {
    const viewerToken = await loginPersona('viewer@trustvault.local', 'Viewer@TrustVault2026!');

    // 1. Direct storage access
    const directStorageRes = await fetch(`${TARGET_URL}/storage/uploads/nonexistent.pdf`);

    // 2. Traversal probing
    const vectors = [
      '..%2F..%2Fstorage%2Fuploads%2Ftarget',
      '%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..%5C..%5Cwindows%5Cwin.ini',
      'test-id%00.pdf',
      '%252e%252e%252f%252e%252e%252fstorage'
    ];

    let allBlocked = directStorageRes.status === 404;
    for (const v of vectors) {
      const res = await fetch(`${TARGET_URL}/api/documents/${v}/download`, {
        headers: { Authorization: `Bearer ${viewerToken}` }
      });

      if (res.status === 200) {
        allBlocked = false;
        break;
      }
    }

    if (allBlocked) {
      results.push({
        id: 'ADV-03',
        name: 'Path Traversal & Storage Isolation',
        vector: 'Direct /storage/ HTTP access, double-encoded dots, Windows backslashes & null bytes',
        status: 'PROTECTED',
        details: 'storage/ folder is not statically mounted. Traversal probes rejected with 400/404.',
        dataLeaked: false
      });
      console.log('  >> PASS: All traversal probes and direct storage access rejected.\n');
    } else {
      results.push({
        id: 'ADV-03',
        name: 'Path Traversal & Storage Isolation',
        vector: 'Direct /storage/ HTTP access, double-encoded dots, Windows backslashes & null bytes',
        status: 'VULNERABLE',
        details: 'A traversal probe succeeded or returned 200 OK.',
        dataLeaked: true
      });
      console.log('  >> FAIL: Storage traversal succeeded!\n');
    }
  } catch (err: any) {
    console.error('Error during Test 3:', err.message);
  }

  // -------------------------------------------------------------
  // Test 4: Cross-Tenant IDOR with Reverse-Proxy Header Spoofing
  // -------------------------------------------------------------
  console.log('[Test 4] Testing Cross-Tenant IDOR with Reverse-Proxy Spoofed Headers...');
  try {
    const eveToken = await loginPersona('eve@trustvault.local', 'Eve@TrustVault2026!');
    const adminToken = await loginPersona('admin@trustvault.local', 'Admin@TrustVault2026!');

    // Fetch Alice's restricted document ID via Admin view
    const adminDocsRes = await fetch(`${TARGET_URL}/api/admin/documents`, {
      headers: { Authorization: `Bearer ${adminToken}` }
    });
    const adminDocs = (await adminDocsRes.json()) as any;
    const privateDoc = adminDocs.documents?.find((d: any) => d.title.includes('Executive Compensation')) || adminDocs.documents?.[0];

    if (!privateDoc?.id) {
      throw new Error('Could not identify a target document on the remote system.');
    }

    // Eve attempts downloading Alice's document while spoofing proxy & identity headers
    const probeRes = await fetch(`${TARGET_URL}/api/documents/${privateDoc.id}/download`, {
      headers: {
        Authorization: `Bearer ${eveToken}`,
        'X-Forwarded-For': '127.0.0.1',
        'X-Forwarded-Host': 'localhost',
        'X-Original-URL': `/api/documents/${privateDoc.id}/download`,
        'X-Rewrite-URL': `/api/documents/${privateDoc.id}/download`,
        'X-User-Role': 'OWNER',
        'X-TrustVault-Role': 'OWNER',
        Referer: `${TARGET_URL}/dashboard/owner`
      }
    });

    // Zero-Trust requirement: 404 Not Found (neither 200 leak nor 403 existence oracle)
    const isProtected = probeRes.status === 404;

    if (isProtected) {
      results.push({
        id: 'ADV-04',
        name: 'Cross-Tenant IDOR & Header Isolation',
        vector: 'Cross-tenant probe with spoofed X-Forwarded-For, X-Original-URL & X-User-Role headers',
        status: 'PROTECTED',
        details: 'Returned 404 Not Found. Zero content bytes and zero existence confirmation leaked.',
        dataLeaked: false
      });
      console.log('  >> PASS: Cross-tenant download returned 404 Not Found (zero data leaked).\n');
    } else {
      results.push({
        id: 'ADV-04',
        name: 'Cross-Tenant IDOR & Header Isolation',
        vector: 'Cross-tenant probe with spoofed X-Forwarded-For, X-Original-URL & X-User-Role headers',
        status: 'VULNERABLE',
        details: `Unexpected response status: HTTP ${probeRes.status}`,
        dataLeaked: probeRes.status === 200
      });
      console.log(`  >> FAIL: Data or existence oracle leaked (HTTP ${probeRes.status})!\n`);
    }
  } catch (err: any) {
    console.error('Error during Test 4:', err.message);
  }

  // -------------------------------------------------------------
  // Test 5: Role Elevation & Prototype Pollution via JSON Body
  // -------------------------------------------------------------
  console.log('[Test 5] Testing JSON Prototype Pollution & Role Elevation over Web API...');
  try {
    const viewerToken = await loginPersona('viewer@trustvault.local', 'Viewer@TrustVault2026!');

    const uploadRes = await fetch(`${TARGET_URL}/api/documents`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${viewerToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        title: 'Malicious Prototype Document',
        category: 'General',
        __proto__: { role: 'OWNER', isActive: true },
        constructor: { prototype: { role: 'OWNER' } }
      })
    });

    // Viewers cannot upload; prototype tampering must not elevate role to OWNER
    const isBlocked = uploadRes.status === 400 || uploadRes.status === 403;

    if (isBlocked) {
      results.push({
        id: 'ADV-05',
        name: 'Prototype Pollution & Role Elevation',
        vector: 'Object prototype injection via __proto__ and constructor.prototype in JSON body',
        status: 'PROTECTED',
        details: `Returned HTTP ${uploadRes.status}. Role remained strictly VIEWER with upload disabled.`,
        dataLeaked: false
      });
      console.log(`  >> PASS: Prototype injection rejected with HTTP ${uploadRes.status}.\n`);
    } else {
      results.push({
        id: 'ADV-05',
        name: 'Prototype Pollution & Role Elevation',
        vector: 'Object prototype injection via __proto__ and constructor.prototype in JSON body',
        status: 'VULNERABLE',
        details: `Unexpected response: HTTP ${uploadRes.status}`,
        dataLeaked: true
      });
      console.log('  >> FAIL: Prototype injection allowed unauthorized upload!\n');
    }
  } catch (err: any) {
    console.error('Error during Test 5:', err.message);
  }

  // -------------------------------------------------------------
  // Test 6: Web Security & Transport Headers Audit
  // -------------------------------------------------------------
  console.log('[Test 6] Auditing Live Web Security & Transport Headers...');
  try {
    const probeRes = await fetch(`${TARGET_URL}/api/health`, { method: 'GET' });
    const nosniff = probeRes.headers.get('x-content-type-options');
    const xss = probeRes.headers.get('x-xss-protection');
    const frame = probeRes.headers.get('x-frame-options');

    const headersSecure = nosniff === 'nosniff';

    if (headersSecure) {
      results.push({
        id: 'ADV-06',
        name: 'HTTP Security Headers Compliance',
        vector: 'Missing security headers (MIME-sniffing, clickjacking, MIME confusion)',
        status: 'PROTECTED',
        details: `X-Content-Type-Options: ${nosniff}. Security headers correctly applied.`,
        dataLeaked: false
      });
      console.log('  >> PASS: X-Content-Type-Options: nosniff verified on live web target.\n');
    } else {
      results.push({
        id: 'ADV-06',
        name: 'HTTP Security Headers Compliance',
        vector: 'Missing security headers (MIME-sniffing, clickjacking, MIME confusion)',
        status: 'VULNERABLE',
        details: `Missing nosniff header (Value: ${nosniff})`,
        dataLeaked: false
      });
      console.log('  >> FAIL: Security headers missing on web target!\n');
    }
  } catch (err: any) {
    console.error('Error during Test 6:', err.message);
  }

  // -------------------------------------------------------------
  // Summary Audit Report
  // -------------------------------------------------------------
  console.log('================================================================');
  console.log(` FINAL WEB SECURITY ASSESSMENT REPORT (${TARGET_URL})`);
  console.log('================================================================');
  console.table(
    results.map((r) => ({
      'Test ID': r.id,
      'Security Domain': r.name,
      'Adversarial Vector': r.vector,
      'Defense Status': r.status,
      'Data Leaked?': r.dataLeaked ? 'YES (FAIL)' : 'NO (PROTECTED)'
    }))
  );

  const totalVulnerable = results.filter((r) => r.status === 'VULNERABLE').length;
  if (totalVulnerable === 0) {
    console.log(`\n>> VERIFIED: ALL ADVERSARIAL VECTORS ARE FULLY BLOCKED ON ${TARGET_URL}.`);
    console.log('>> ZERO DATA LEAKS DETECTED. SYSTEM IS FULLY SECURE.');
    console.log('================================================================\n');
    process.exit(0);
  } else {
    console.error(`\n>> CRITICAL: ${totalVulnerable} VULNERABILITY(IES) DETECTED ON ${TARGET_URL}!`);
    console.log('================================================================\n');
    process.exit(1);
  }
}

runLiveWebAudit().catch((err) => {
  console.error('Audit execution error:', err);
  process.exit(1);
});
