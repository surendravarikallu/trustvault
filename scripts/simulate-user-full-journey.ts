/**
 * TrustVault Comprehensive User Journey Simulation
 * 
 * Tests:
 * 1. Alice (Owner) uploads document with encryption.
 * 2. Alice shares Document A with Bob as PREVIEW-ONLY (download blocked).
 * 3. Alice shares Document B with Bob as BURN-ON-DOWNLOAD (auto-revocation).
 * 4. Bob logs in:
 *    - Sees Document A with Preview-Only badge.
 *    - Streams preview of Document A (HTTP 200).
 *    - Attempts download of Document A (Blocked: HTTP 403 with policy error).
 *    - Sees Document B with Burn-on-Download badge.
 *    - Downloads Document B (HTTP 200).
 *    - Verifies Document B is burned/revoked (Subsequent access returns 404).
 * 5. Eve (Adversary) logs in:
 *    - Sees 0 documents in vault.
 *    - Probes Alice's document directly (Returns 404 Fail-Closed).
 * 6. Admin logs in:
 *    - Verifies HMAC audit chain integrity.
 *    - Inspects audit logs capturing all actions, grants, burns, and denied attempts.
 */
export {};

const BASE_URL = process.env.TARGET_URL || 'http://127.0.0.1:7777';

interface SimulationReport {
  steps: {
    step: number;
    name: string;
    persona: string;
    action: string;
    expected: string;
    actual: string;
    status: 'PASS' | 'FAIL' | 'BUG_DETECTED';
    details?: any;
  }[];
  findings: string[];
}

const report: SimulationReport = {
  steps: [],
  findings: []
};

async function login(usernameOrEmail: string, password: string) {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernameOrEmail, password })
  });
  const data = await res.json();
  if (!res.ok) throw new Error(`Login failed for ${usernameOrEmail}: ${data.error}`);
  return data;
}

async function uploadPdf(token: string, title: string, filename: string) {
  const boundary = '----TrustVaultMultipartBoundary' + Math.random().toString(36).substring(2);
  const pdfHeader = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (' + title + ') >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');

  let body = '';
  body += `--${boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\n${title}\r\n`;
  body += `--${boundary}\r\nContent-Disposition: form-data; name="category"\r\n\r\nLegal\r\n`;
  body += `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/pdf\r\n\r\n`;

  const bodyStart = Buffer.from(body, 'utf-8');
  const bodyEnd = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8');
  const fullBody = Buffer.concat([bodyStart, pdfHeader, bodyEnd]);

  const res = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': `multipart/form-data; boundary=${boundary}`
    },
    body: fullBody
  });

  const data = await res.json();
  if (!res.ok) throw new Error(`Upload failed: ${data.error}`);
  return data.document || data;
}

async function grantAccess(token: string, docId: string, targetEmail: string, permissionLevel: 'READ' | 'EDIT', options?: { previewOnly?: boolean; burnOnDownload?: boolean }) {
  const res = await fetch(`${BASE_URL}/api/documents/${docId}/permissions`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      targetEmail,
      permissionLevel,
      previewOnly: options?.previewOnly,
      burnOnDownload: options?.burnOnDownload
    })
  });

  const data = await res.json();
  return { status: res.status, data };
}

async function listVault(token: string) {
  const res = await fetch(`${BASE_URL}/api/documents`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const data = await res.json();
  return { status: res.status, documents: data.documents || [] };
}

async function downloadDoc(token: string, docId: string, preview = false) {
  const url = preview ? `${BASE_URL}/api/documents/${docId}/download?preview=true` : `${BASE_URL}/api/documents/${docId}/download`;
  const res = await fetch(url, {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  let data: any = null;
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    data = await res.json().catch(() => null);
  } else {
    const buf = await res.arrayBuffer();
    data = { byteLength: buf.byteLength, contentDisposition: res.headers.get('content-disposition') };
  }

  return { status: res.status, contentType, data };
}

async function run() {
  console.log('================================================================');
  console.log(' TRUSTVAULT: COMPREHENSIVE MULTI-USER JOURNEY SIMULATION');
  console.log('================================================================\n');

  // STEP 1: ALICE (OWNER) LOGS IN AND UPLOADS TWO DOCUMENTS
  const alice = await login('owner', 'Owner@TrustVault2026!');
  console.log(`[1] Logged in as Alice (OWNER): ${alice.user.email}`);

  const docPreview = await uploadPdf(alice.token, 'Confidential Acquisition Term Sheet (Preview Only)', 'Acquisition_Term_Sheet.pdf');
  console.log(`[2] Alice uploaded Doc A (ID: ${docPreview.id}) - "Confidential Acquisition Term Sheet"`);

  const docBurn = await uploadPdf(alice.token, 'Wire Transfer Authorization Code (Single-Use)', 'Wire_Transfer_Auth.pdf');
  console.log(`[3] Alice uploaded Doc B (ID: ${docBurn.id}) - "Wire Transfer Authorization Code"`);

  // STEP 2: ALICE DELEGATES PREVIEW-ONLY PERMISSION TO BOB
  const grantRes1 = await grantAccess(alice.token, docPreview.id, 'viewer@trustvault.local', 'READ', { previewOnly: true });
  console.log(`[4] Alice granted PREVIEW-ONLY access on Doc A to Bob: HTTP ${grantRes1.status}`);

  // STEP 3: ALICE DELEGATES BURN-ON-DOWNLOAD PERMISSION TO BOB
  const grantRes2 = await grantAccess(alice.token, docBurn.id, 'viewer@trustvault.local', 'READ', { burnOnDownload: true });
  console.log(`[5] Alice granted BURN-ON-DOWNLOAD access on Doc B to Bob: HTTP ${grantRes2.status}`);

  // STEP 4: BOB (VIEWER) LOGS IN AND INSPECTS VAULT
  const bob = await login('viewer', 'Viewer@TrustVault2026!');
  console.log(`\n[6] Logged in as Bob (VIEWER): ${bob.user.email}`);

  const bobVault = await listVault(bob.token);
  console.log(`[7] Bob lists vault: sees ${bobVault.documents.length} documents total.`);

  const bobDocA = bobVault.documents.find((d: any) => d.id === docPreview.id);
  const bobDocB = bobVault.documents.find((d: any) => d.id === docBurn.id);

  console.log(`    - Doc A visible: ${!!bobDocA} (PreviewOnly flag: ${bobDocA?.permissions?.[0]?.previewOnly})`);
  console.log(`    - Doc B visible: ${!!bobDocB} (BurnOnDownload flag: ${bobDocB?.permissions?.[0]?.burnOnDownload})`);

  // STEP 5: BOB ATTEMPTS TO PREVIEW DOC A (SHOULD SUCCEED WITH INLINE STREAM)
  const previewDocA = await downloadDoc(bob.token, docPreview.id, true);
  console.log(`\n[8] Bob in-browser preview on Doc A: HTTP ${previewDocA.status} (${previewDocA.data?.byteLength} bytes, header: ${previewDocA.data?.contentDisposition})`);

  // STEP 6: BOB ATTEMPTS UNAUTHORIZED BINARY DOWNLOAD ON DOC A (SHOULD BE BLOCKED HTTP 403)
  const downloadDocA = await downloadDoc(bob.token, docPreview.id, false);
  console.log(`[9] Bob binary download attempt on Doc A (Preview-Only): HTTP ${downloadDocA.status}`);
  console.log(`    Response error: "${downloadDocA.data?.error}"`);

  // STEP 7: BOB DOWNLOADS DOC B (BURN-ON-DOWNLOAD PROTOCOL)
  const downloadDocB = await downloadDoc(bob.token, docBurn.id, false);
  console.log(`\n[10] Bob downloads Doc B (Burn-on-Download): HTTP ${downloadDocB.status} (${downloadDocB.data?.byteLength} bytes)`);

  // Allow asynchronous res.on('finish') auto-revocation to execute in DB
  await new Promise((r) => setTimeout(r, 600));

  // STEP 8: BOB RE-INSPECTS VAULT AFTER DOWNLOAD (DOC B MUST BE AUTO-REVOKED)
  const bobVaultAfterBurn = await listVault(bob.token);
  const bobDocBAfter = bobVaultAfterBurn.documents.find((d: any) => d.id === docBurn.id);
  console.log(`[11] Bob re-inspects vault after downloading Doc B:`);
  console.log(`     - Doc B visible in list: ${!!bobDocBAfter} (Expected: false)`);

  // STEP 9: BOB ATTEMPTS SECOND DOWNLOAD ON BURNED DOC B (MUST RETURN 404 NOT FOUND)
  const probeBurnedDocB = await downloadDoc(bob.token, docBurn.id, false);
  console.log(`[12] Bob probes burned Doc B again: HTTP ${probeBurnedDocB.status} (Expected: 404 Fail-Closed)`);

  // STEP 10: EVE (ADVERSARY) LOGS IN AND CHECKS ISOLATION
  const eve = await login('eve', 'Eve@TrustVault2026!');
  console.log(`\n[13] Logged in as Eve (ADVERSARY): ${eve.user.email}`);

  const eveVault = await listVault(eve.token);
  console.log(`[14] Eve vault document count: ${eveVault.documents.length} (Expected: 0)`);

  const eveProbeDocA = await downloadDoc(eve.token, docPreview.id);
  console.log(`[15] Eve probing Alice's Doc A: HTTP ${eveProbeDocA.status} (Expected: 404 Not Found)`);

  const eveProbeDocB = await downloadDoc(eve.token, docBurn.id);
  console.log(`[16] Eve probing Alice's Doc B: HTTP ${eveProbeDocB.status} (Expected: 404 Not Found)`);

  // STEP 11: ADMIN AUDITS AND VERIFIES CRYPTOGRAPHIC INTEGRITY
  const admin = await login('admin', 'Admin@TrustVault2026!');
  console.log(`\n[17] Logged in as Admin (AUDITOR): ${admin.user.email}`);

  const verifyRes = await fetch(`${BASE_URL}/api/admin/audit-verify`, {
    headers: { 'Authorization': `Bearer ${admin.token}` }
  });
  const verifyData = await verifyRes.json();
  console.log(`[18] Cryptographic HMAC Chain Integrity: ${verifyData.valid}`);
  console.log(`     Total Chained Records: ${verifyData.totalRecords}`);
  console.log(`     Ledger Head Hash:      ${verifyData.headHash}`);

  // Fetch recent audit logs to check forensic record
  const auditLogsRes = await fetch(`${BASE_URL}/api/admin/audit?limit=15`, {
    headers: { 'Authorization': `Bearer ${admin.token}` }
  });
  const auditLogsData = await auditLogsRes.json();
  console.log(`[19] Recent audit events recorded in ledger:`);
  for (const log of (auditLogsData.logs || []).slice(0, 8)) {
    console.log(`     - [Seq #${log.sequenceNumber}] ${log.action} | Status: ${log.status} | Actor: ${log.userEmail || 'anonymous'}`);
  }

  console.log('\n================================================================');
  console.log(' COMPREHENSIVE SIMULATION FINISHED');
  console.log('================================================================');
}

run().catch(console.error);
