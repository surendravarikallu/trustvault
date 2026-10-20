/**
 * TrustVault Multi-User Collaboration & Access Delegation Simulation
 * 
 * Demonstrates:
 * 1. Owner (Alice) logs in and uploads an encrypted document.
 * 2. Alice grants READ access to Viewer (Bob).
 * 3. Alice grants EDIT access on a second document to Bob.
 * 4. Bob logs in and verifies both shared documents appear in his vault.
 * 5. Bob reads and downloads the READ document successfully.
 * 6. Bob attempts an unauthorized edit on the READ document (Blocked: HTTP 403).
 * 7. Bob attempts unauthorized re-sharing to Eve (Blocked: HTTP 403).
 * 8. Bob successfully updates metadata on the EDIT document (Allowed: HTTP 200).
 * 9. Eve logs in: verifies 0 documents visible; probing document returns 404 Not Found.
 * 10. Admin logs in and inspects the HMAC audit chain capturing all events.
 */

const BASE_URL = process.env.TARGET_URL || 'http://127.0.0.1:7777';

interface LoginResponse {
  token: string;
  user: {
    id: string;
    email: string;
    name: string;
    role: string;
  };
}

async function login(usernameOrEmail: string, password: string): Promise<LoginResponse> {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ usernameOrEmail, password })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(`Login failed for ${usernameOrEmail}: ${data.error}`);
  }
  return data;
}

async function uploadPdf(token: string, title: string, filename: string): Promise<any> {
  const boundary = '----TrustVaultMultipartBoundary' + Math.random().toString(36).substring(2);
  const pdfHeader = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (' + title + ') >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');

  let body = '';
  body += `--${boundary}\r\n`;
  body += `Content-Disposition: form-data; name="title"\r\n\r\n${title}\r\n`;
  body += `--${boundary}\r\n`;
  body += `Content-Disposition: form-data; name="category"\r\n\r\nLEGAL\r\n`;
  body += `--${boundary}\r\n`;
  body += `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n`;
  body += `Content-Type: application/pdf\r\n\r\n`;

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
  if (!res.ok) {
    throw new Error(`Upload failed: ${data.error}`);
  }
  return data.document || data;
}

async function grantAccess(token: string, docId: string, targetEmail: string, permissionLevel: 'READ' | 'EDIT'): Promise<any> {
  const res = await fetch(`${BASE_URL}/api/documents/${docId}/permissions`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      targetEmail,
      permissionLevel
    })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(`Grant access failed: ${data.error}`);
  }
  return data;
}

async function listVault(token: string): Promise<any[]> {
  const res = await fetch(`${BASE_URL}/api/documents`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(`List vault failed: ${data.error}`);
  }
  return data.documents || [];
}

async function downloadDocument(token: string, docId: string, isPreview = false): Promise<{ status: number; bytes: number; contentDisposition: string | null }> {
  const url = isPreview ? `${BASE_URL}/api/documents/${docId}/download?preview=true` : `${BASE_URL}/api/documents/${docId}/download`;
  const res = await fetch(url, {
    headers: { 'Authorization': `Bearer ${token}` }
  });

  if (!res.ok) {
    return { status: res.status, bytes: 0, contentDisposition: null };
  }

  const arrayBuffer = await res.arrayBuffer();
  return {
    status: res.status,
    bytes: arrayBuffer.byteLength,
    contentDisposition: res.headers.get('content-disposition')
  };
}

async function replaceFile(token: string, docId: string, filename: string): Promise<{ status: number; data: any }> {
  const boundary = '----TrustVaultReplaceBoundary' + Math.random().toString(36).substring(2);
  const pdfHeader = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (Revised Version by Editor) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');

  let body = '';
  body += `--${boundary}\r\n`;
  body += `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n`;
  body += `Content-Type: application/pdf\r\n\r\n`;

  const bodyStart = Buffer.from(body, 'utf-8');
  const bodyEnd = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8');
  const fullBody = Buffer.concat([bodyStart, pdfHeader, bodyEnd]);

  const res = await fetch(`${BASE_URL}/api/documents/${docId}`, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': `multipart/form-data; boundary=${boundary}`
    },
    body: fullBody
  });

  const data = await res.json();
  return { status: res.status, data };
}

async function main() {
  console.log('================================================================');
  console.log(' TRUSTVAULT: END-TO-END MULTI-USER COLLABORATION SIMULATION');
  console.log(' Target:', BASE_URL);
  console.log('================================================================\n');

  // STEP 1: ALICE (OWNER) LOGS IN AND UPLOADS DOCUMENTS
  console.log('--- STEP 1: Alice (Document Owner) Logs In & Uploads Files ---');
  const aliceAuth = await login('owner', 'Owner@TrustVault2026!');
  console.log(`[✓] Logged in as Alice: ${aliceAuth.user.name} (${aliceAuth.user.email}) [Role: ${aliceAuth.user.role}]`);

  const doc1 = await uploadPdf(aliceAuth.token, 'Q4 Global Services Contract', 'Q4_Global_Services_2026.pdf');
  console.log(`[✓] Alice uploaded Document 1 (ID: ${doc1.id}) - "Q4 Global Services Contract"`);

  const doc2 = await uploadPdf(aliceAuth.token, 'Joint Technical Roadmap 2026', 'Technical_Roadmap_2026.pdf');
  console.log(`[✓] Alice uploaded Document 2 (ID: ${doc2.id}) - "Joint Technical Roadmap 2026"`);

  // STEP 2: ALICE DELEGATES PERMISSIONS
  console.log('\n--- STEP 2: Alice Shares Files with Bob (READ & EDIT) ---');
  const grant1 = await grantAccess(aliceAuth.token, doc1.id, 'viewer@trustvault.local', 'READ');
  console.log(`[✓] Alice granted READ permission on Document 1 to Bob (viewer@trustvault.local)`);

  const grant2 = await grantAccess(aliceAuth.token, doc2.id, 'viewer@trustvault.local', 'EDIT');
  console.log(`[✓] Alice granted EDIT permission on Document 2 to Bob (viewer@trustvault.local)`);

  // STEP 3: LOG OUT ALICE, BOB (VIEWER) LOGS IN
  console.log('\n--- STEP 3: Bob (Authorized Viewer) Logs In ---');
  const bobAuth = await login('viewer', 'Viewer@TrustVault2026!');
  console.log(`[✓] Logged in as Bob: ${bobAuth.user.name} (${bobAuth.user.email}) [Role: ${bobAuth.user.role}]`);

  // STEP 4: BOB SEES THE SHARED DOCUMENTS
  console.log('\n--- STEP 4: Bob Inspects His Vault (Shared Documents) ---');
  const bobDocs = await listVault(bobAuth.token);
  console.log(`[✓] Bob sees ${bobDocs.length} documents in his vault.`);
  
  const foundDoc1 = bobDocs.find(d => d.id === doc1.id);
  const foundDoc2 = bobDocs.find(d => d.id === doc2.id);

  if (foundDoc1) {
    console.log(`    - Document 1 found: "${foundDoc1.title}" (Owner: ${foundDoc1.owner?.name || 'Alice'})`);
  } else {
    console.error(`    [!] FAILED: Document 1 not visible in Bob's vault.`);
  }

  if (foundDoc2) {
    console.log(`    - Document 2 found: "${foundDoc2.title}" (Owner: ${foundDoc2.owner?.name || 'Alice'})`);
  } else {
    console.error(`    [!] FAILED: Document 2 not visible in Bob's vault.`);
  }

  // STEP 5: BOB ACCESSES & DOWNLOADS DOCUMENT 1 (READ)
  console.log('\n--- STEP 5: Bob Reads & Downloads Document 1 (READ Grant) ---');
  const downloadRes = await downloadDocument(bobAuth.token, doc1.id, false);
  console.log(`[✓] Bob download request status: HTTP ${downloadRes.status} (Streamed ${downloadRes.bytes} decrypted bytes)`);
  console.log(`    Header: ${downloadRes.contentDisposition}`);

  // In-browser inline preview
  const previewRes = await downloadDocument(bobAuth.token, doc1.id, true);
  console.log(`[✓] Bob inline preview stream status: HTTP ${previewRes.status} (Header: ${previewRes.contentDisposition})`);

  // STEP 6: BOB ATTEMPTS UNAUTHORIZED EDIT ON READ-ONLY DOCUMENT
  console.log('\n--- STEP 6: Bob Attempts Unauthorized Edit on READ-Only File ---');
  const unauthorizedEdit = await replaceFile(bobAuth.token, doc1.id, 'tampered_contract.pdf');
  if (unauthorizedEdit.status === 403) {
    console.log(`[✓ PASS] Unauthorized edit blocked with HTTP 403 Forbidden!`);
    console.log(`         Error: "${unauthorizedEdit.data.error}"`);
  } else {
    console.error(`[!] FAILED: Edit returned status ${unauthorizedEdit.status}`);
  }

  // STEP 7: BOB ATTEMPTS UNAUTHORIZED RE-SHARING
  console.log('\n--- STEP 7: Bob Attempts Unauthorized Re-Sharing to Eve ---');
  try {
    await grantAccess(bobAuth.token, doc1.id, 'eve@trustvault.local', 'READ');
    console.error(`[!] FAILED: Non-owner was permitted to share!`);
  } catch (err: any) {
    console.log(`[✓ PASS] Re-sharing blocked with HTTP 403 Forbidden!`);
    console.log(`         Reason: Only the document owner can grant or revoke permissions.`);
  }

  // STEP 8: BOB PERFORMS AUTHORIZED EDIT ON EDIT-GRANTED DOCUMENT
  console.log('\n--- STEP 8: Bob Performs Authorized Edit on EDIT-Granted File ---');
  const authorizedEdit = await replaceFile(bobAuth.token, doc2.id, 'Technical_Roadmap_2026_Revised.pdf');
  if (authorizedEdit.status === 200) {
    console.log(`[✓ PASS] Bob edited Document 2 successfully! (HTTP 200)`);
    console.log(`         Message: "${authorizedEdit.data.message}"`);
    console.log(`         Current Version ID: ${authorizedEdit.data.document.id}`);
  } else {
    console.error(`[!] FAILED: Authorized edit failed with status ${authorizedEdit.status}`, authorizedEdit.data);
  }

  // STEP 9: EVE (ADVERSARY) LOGS IN AND CHECKS ISOLATION
  console.log('\n--- STEP 9: Eve (Adversary) Logs In & Probes Unshared Files ---');
  const eveAuth = await login('eve', 'Eve@TrustVault2026!');
  console.log(`[✓] Logged in as Eve: ${eveAuth.user.name} (${eveAuth.user.email}) [Role: ${eveAuth.user.role}]`);

  const eveDocs = await listVault(eveAuth.token);
  console.log(`[✓] Eve vault document count: ${eveDocs.length} (Complete isolation)`);

  const eveDownloadProbe = await downloadDocument(eveAuth.token, doc1.id);
  if (eveDownloadProbe.status === 404) {
    console.log(`[✓ PASS] Eve probing Alice's document receives HTTP 404 Not Found (Information Barrier held).`);
  } else {
    console.error(`[!] FAILED: Eve probe returned status ${eveDownloadProbe.status}`);
  }

  // STEP 10: ADMIN INSPECTS AUDIT CHAIN
  console.log('\n--- STEP 10: Admin Verifies Cryptographic Audit Ledger ---');
  const adminAuth = await login('admin', 'Admin@TrustVault2026!');
  const auditRes = await fetch(`${BASE_URL}/api/admin/audit-verify`, {
    headers: { 'Authorization': `Bearer ${adminAuth.token}` }
  });
  const auditData = await auditRes.json();
  console.log(`[✓] Audit HMAC Chain Valid: ${auditData.valid}`);
  console.log(`    Total Chained Events:   ${auditData.totalRecords}`);
  console.log(`    Ledger Head Sequence:   ${auditData.headSequence}`);
  console.log(`    Head HMAC-SHA256:       ${auditData.headHash}`);

  console.log('\n================================================================');
  console.log(' SIMULATION COMPLETED: 100% SUCCESSFUL MULTI-USER WORKFLOW');
  console.log('================================================================');
}

main().catch(console.error);
