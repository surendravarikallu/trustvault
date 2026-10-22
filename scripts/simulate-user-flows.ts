import fs from 'fs';
import path from 'path';

interface SimulationReport {
  persona: string;
  flow: string;
  action: string;
  expectedStatus: number | string;
  actualStatus: number | string;
  passed: boolean;
  notes?: string;
  bugOrIssue?: string;
}

const BASE_URL = 'http://127.0.0.1:7777';
const reports: SimulationReport[] = [];

function record(report: SimulationReport) {
  reports.push(report);
  const mark = report.passed ? '✓ PASS' : '✗ FAIL/BUG';
  console.log(`[${mark}] ${report.persona} - ${report.action}: ${report.notes || ''}`);
  if (report.bugOrIssue) {
    console.warn(`    -> ISSUE IDENTIFIED: ${report.bugOrIssue}`);
  }
}

async function apiRequest(
  method: string,
  endpoint: string,
  body?: any,
  token?: string,
  isMultipart = false
) {
  const headers: Record<string, string> = {};
  if (token) {
    if (token.startsWith('__Host-') || token.includes('=')) {
      headers['Cookie'] = token;
    } else {
      headers['Cookie'] = `__Host-trustvault_token=${token}`;
    }
  }
  if (!isMultipart && body) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${BASE_URL}${endpoint}`, {
    method,
    headers,
    body: isMultipart ? body : (body ? JSON.stringify(body) : undefined)
  });

  const contentType = res.headers.get('content-type') || '';
  let data: any = null;
  if (contentType.includes('application/json')) {
    try {
      data = await res.json();
    } catch {
      data = null;
    }
  } else {
    data = await res.text();
  }

  const setCookie = res.headers.get('set-cookie');
  const cookie = setCookie ? setCookie.split(';')[0] : undefined;
  if (cookie && data && typeof data === 'object') {
    data.token = cookie;
  }

  return { status: res.status, headers: res.headers, data, cookie };
}

async function runSimulation() {
  console.log('================================================================');
  console.log('TRUSTVALT END-TO-END USER SIMULATION & BUG DISCOVERY RUN');
  console.log('Target:', BASE_URL);
  console.log('================================================================\n');

  // --- HEALTH & TELEMETRY CHECK ---
  console.log('--- Checking Deep Health & System Telemetry ---');
  try {
    const health = await apiRequest('GET', '/api/health');
    record({
      persona: 'System',
      flow: 'Health Probe',
      action: 'GET /api/health',
      expectedStatus: 200,
      actualStatus: health.status,
      passed: health.status === 200 && (health.data?.status === 'ok' || health.data?.database?.status === 'connected'),
      notes: `Health response: ${JSON.stringify(health.data)}`
    });
  } catch (err: any) {
    record({
      persona: 'System',
      flow: 'Health Probe',
      action: 'GET /api/health',
      expectedStatus: 200,
      actualStatus: 'CONNECTION_ERROR',
      passed: false,
      bugOrIssue: `Server not responding on ${BASE_URL}: ${err.message}`
    });
    return;
  }

  // --- PERSONA 1: SECURITY ADMINISTRATOR ---
  console.log('\n--- SIMULATING PERSONA 1: SECURITY ADMINISTRATOR ---');
  // 1.1 Login with short username 'admin'
  const adminLoginShort = await apiRequest('POST', '/api/auth/login', {
    usernameOrEmail: 'admin',
    password: 'Admin@TrustVault2026!'
  });
  record({
    persona: 'Admin',
    flow: 'Authentication',
    action: 'Login via short username (admin)',
    expectedStatus: 200,
    actualStatus: adminLoginShort.status,
    passed: adminLoginShort.status === 200 && !!adminLoginShort.data?.token,
    notes: `Role: ${adminLoginShort.data?.user?.role}, TokenVersion: ${adminLoginShort.data?.user?.tokenVersion}`
  });

  // 1.2 Login with full email 'admin@trustvault.local'
  const adminLogin = await apiRequest('POST', '/api/auth/login', {
    usernameOrEmail: 'admin@trustvault.local',
    password: 'Admin@TrustVault2026!'
  });
  const adminToken = adminLogin.data?.token;

  // 1.3 View Governance Documents
  const adminDocs = await apiRequest('GET', '/api/admin/documents', null, adminToken);
  record({
    persona: 'Admin',
    flow: 'Governance Inspection',
    action: 'GET /api/admin/documents',
    expectedStatus: 200,
    actualStatus: adminDocs.status,
    passed: adminDocs.status === 200 && Array.isArray(adminDocs.data?.documents || adminDocs.data),
    notes: `Found ${adminDocs.data?.documents?.length || adminDocs.data?.length || 0} registered governance documents.`
  });

  // 1.4 Admin Zero-Trust Rule: Admin CANNOT download private document without grant
  const docList = adminDocs.data?.documents || adminDocs.data || [];
  const testDoc = docList.find((d: any) => d.owner?.email !== 'admin@trustvault.local' && d.ownerId !== adminLoginShort.data?.user?.id) || docList[0];
  if (testDoc) {
    const adminDownloadProbe = await apiRequest('GET', `/api/documents/${testDoc.id}/download`, null, adminToken);
    record({
      persona: 'Admin',
      flow: 'Zero-Trust Boundary',
      action: `Admin downloads private document without grant (${testDoc.originalFilename})`,
      expectedStatus: '403 or 404',
      actualStatus: adminDownloadProbe.status,
      passed: adminDownloadProbe.status === 403 || adminDownloadProbe.status === 404,
      notes: `Admin received HTTP ${adminDownloadProbe.status} (Zero-Trust barrier held).`
    });
  }

  // 1.5 View Audit Ledger
  const auditLogs = await apiRequest('GET', '/api/admin/audit-logs', null, adminToken);
  record({
    persona: 'Admin',
    flow: 'Audit Oversight',
    action: 'GET /api/admin/audit-logs',
    expectedStatus: 200,
    actualStatus: auditLogs.status,
    passed: auditLogs.status === 200 && (Array.isArray(auditLogs.data?.logs) || Array.isArray(auditLogs.data)),
    notes: `Fetched audit entries successfully.`
  });

  // 1.6 Verify Cryptographic HMAC Hash Chain
  const auditVerify = await apiRequest('GET', '/api/admin/audit-verify', null, adminToken);
  record({
    persona: 'Admin',
    flow: 'Ledger Verification',
    action: 'GET /api/admin/audit-verify',
    expectedStatus: 200,
    actualStatus: auditVerify.status,
    passed: auditVerify.status === 200 && auditVerify.data?.valid === true,
    notes: `HMAC Chain Valid: ${auditVerify.data?.valid}, Total Records: ${auditVerify.data?.totalRecords}`
  });

  // 1.7 View User Directory
  const userList = await apiRequest('GET', '/api/admin/users', null, adminToken);
  record({
    persona: 'Admin',
    flow: 'Identity Management',
    action: 'GET /api/admin/users',
    expectedStatus: 200,
    actualStatus: userList.status,
    passed: userList.status === 200 && (Array.isArray(userList.data?.users) || Array.isArray(userList.data)),
    notes: `Users found: ${userList.data?.users?.length || userList.data?.length}`
  });

  // 1.8 Create and Verify Backup
  const backupCreate = await apiRequest('POST', '/api/admin/backups', null, adminToken);
  record({
    persona: 'Admin',
    flow: 'Disaster Recovery',
    action: 'POST /api/admin/backups',
    expectedStatus: 201,
    actualStatus: backupCreate.status,
    passed: backupCreate.status === 201 || backupCreate.status === 200,
    notes: `Backup filename: ${backupCreate.data?.backupFilename || backupCreate.data?.filename || 'created'}`
  });

  const backupVerify = await apiRequest('POST', '/api/admin/backups/verify', {
    backupId: backupCreate.data?.backupId
  }, adminToken);
  record({
    persona: 'Admin',
    flow: 'Disaster Recovery',
    action: 'POST /api/admin/backups/verify',
    expectedStatus: 200,
    actualStatus: backupVerify.status,
    passed: backupVerify.status === 200 && backupVerify.data?.isValid === true,
    notes: `Backup HMAC Manifest Valid: ${backupVerify.data?.isValid}`
  });

  // --- PERSONA 2: ALICE (DOCUMENT OWNER) ---
  console.log('\n--- SIMULATING PERSONA 2: ALICE (DOCUMENT OWNER) ---');
  // 2.1 Login
  const ownerLogin = await apiRequest('POST', '/api/auth/login', {
    usernameOrEmail: 'owner',
    password: 'Owner@TrustVault2026!'
  });
  record({
    persona: 'Owner (Alice)',
    flow: 'Authentication',
    action: 'Login via short username (owner)',
    expectedStatus: 200,
    actualStatus: ownerLogin.status,
    passed: ownerLogin.status === 200 && !!ownerLogin.data?.token,
    notes: `Name: ${ownerLogin.data?.user?.name}, Role: ${ownerLogin.data?.user?.role}`
  });
  const ownerToken = ownerLogin.data?.token;

  // 2.2 List Documents
  const ownerDocs = await apiRequest('GET', '/api/documents', null, ownerToken);
  const ownerDocList: any[] = ownerDocs.data?.documents || ownerDocs.data || [];
  record({
    persona: 'Owner (Alice)',
    flow: 'Document Management',
    action: 'GET /api/documents (List documents)',
    expectedStatus: 200,
    actualStatus: ownerDocs.status,
    passed: ownerDocs.status === 200 && ownerDocList.length > 0,
    notes: `Alice sees ${ownerDocList.length} documents.`
  });

  // 2.3 Search Documents
  const searchResult = await apiRequest('GET', '/api/documents/search?q=Incident', null, ownerToken);
  const searchDocs: any[] = searchResult.data?.documents || searchResult.data || [];
  record({
    persona: 'Owner (Alice)',
    flow: 'Search',
    action: 'GET /api/documents/search?q=Incident',
    expectedStatus: 200,
    actualStatus: searchResult.status,
    passed: searchResult.status === 200 && searchDocs.length > 0,
    notes: `Found ${searchDocs.length} matching documents.`
  });

  // 2.4 Download Document & In-Browser Ephemeral Preview
  const msaDoc = ownerDocList.find((d: any) => d.originalFilename === 'MSA_Acme_2026.pdf') || ownerDocList[0];
  if (msaDoc) {
    // Normal Download
    const downloadRes = await apiRequest('GET', `/api/documents/${msaDoc.id}/download`, null, ownerToken);
    record({
      persona: 'Owner (Alice)',
      flow: 'File Retrieval',
      action: `Download document (${msaDoc.originalFilename})`,
      expectedStatus: 200,
      actualStatus: downloadRes.status,
      passed: downloadRes.status === 200 && (downloadRes.headers.get('content-disposition')?.includes('attachment') ?? false),
      notes: `Downloaded ${downloadRes.data?.length || 0} bytes. Header: ${downloadRes.headers.get('content-disposition')}`
    });

    // Preview streaming
    const previewRes = await apiRequest('GET', `/api/documents/${msaDoc.id}/download?is_preview=true`, null, ownerToken);
    record({
      persona: 'Owner (Alice)',
      flow: 'Ephemeral Preview',
      action: `Inline preview streaming (${msaDoc.originalFilename})`,
      expectedStatus: 200,
      actualStatus: previewRes.status,
      passed: previewRes.status === 200 && ((previewRes.headers.get('content-disposition')?.includes('attachment') || previewRes.headers.get('content-disposition')?.includes('inline')) ?? false),
      notes: `Preview stream header: ${previewRes.headers.get('content-disposition')}`
    });

    // Version history
    const versionsRes = await apiRequest('GET', `/api/documents/${msaDoc.id}/versions`, null, ownerToken);
    record({
      persona: 'Owner (Alice)',
      flow: 'Version Retention',
      action: `GET /api/documents/:id/versions`,
      expectedStatus: 200,
      actualStatus: versionsRes.status,
      passed: versionsRes.status === 200,
      notes: `Versions list accessible.`
    });

    // AI Reviewer Suggestions
    const aiSuggestRes = await apiRequest('POST', `/api/documents/${msaDoc.id}/ai-share-suggest`, null, ownerToken);
    record({
      persona: 'Owner (Alice)',
      flow: 'AI Delegation Helper',
      action: `POST /api/documents/:id/ai-share-suggest`,
      expectedStatus: 200,
      actualStatus: aiSuggestRes.status,
      passed: aiSuggestRes.status === 200 && Array.isArray(aiSuggestRes.data?.suggestions || aiSuggestRes.data),
      notes: `AI suggested ${aiSuggestRes.data?.suggestions?.length || aiSuggestRes.data?.length || 0} reviewers.`
    });

    // List Grantees
    const granteesRes = await apiRequest('GET', `/api/documents/${msaDoc.id}/permissions`, null, ownerToken);
    record({
      persona: 'Owner (Alice)',
      flow: 'Access Delegation',
      action: `GET /api/documents/:id/permissions`,
      expectedStatus: 200,
      actualStatus: granteesRes.status,
      passed: granteesRes.status === 200,
      notes: `Grantees fetched.`
    });
  }

  // 2.5 Upload Real Document as Alice (Multipart Form)
  const boundary = '----WebKitFormBoundarySimTest' + Date.now();
  const testPdfContent = '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n4 0 obj\n<< /Length 44 >>\nstream\nBT /F1 12 Tf 100 700 Td (Simulated Real Upload) Tj ET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \n0000000214 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n308\n%%EOF\n';
  
  const formPayload = [
    `--${boundary}`,
    'Content-Disposition: form-data; name="title"',
    '',
    'Simulated Q4 Audit Attestation',
    `--${boundary}`,
    'Content-Disposition: form-data; name="category"',
    '',
    'Compliance',
    `--${boundary}`,
    'Content-Disposition: form-data; name="description"',
    '',
    'Simulated realistic compliance attestation document.',
    `--${boundary}`,
    'Content-Disposition: form-data; name="file"; filename="Simulated_Attestation_2026.pdf"',
    'Content-Type: application/pdf',
    '',
    testPdfContent,
    `--${boundary}--`
  ].join('\r\n');

  const uploadRes = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: {
      'Cookie': ownerToken,
      'Content-Type': `multipart/form-data; boundary=${boundary}`
    },
    body: formPayload
  });

  const uploadData: any = await uploadRes.json();
  record({
    persona: 'Owner (Alice)',
    flow: 'Upload Hardening',
    action: 'POST /api/documents (Upload authentic PDF)',
    expectedStatus: 201,
    actualStatus: uploadRes.status,
    passed: uploadRes.status === 201 && !!uploadData?.id,
    notes: `Uploaded doc ID: ${uploadData?.id}, Hash: ${uploadData?.fileHash?.slice(0, 12)}...`
  });

  const createdSimDocId = uploadData?.id;

  // 2.6 Grant Advanced Ephemeral Access: Burn-on-Download to Bob
  const viewerLookup = await apiRequest('GET', '/api/auth/lookup?email=viewer@trustvault.local', null, ownerToken);
  const bobUserId = viewerLookup.data?.user?.id || viewerLookup.data?.id;

  if (createdSimDocId && bobUserId) {
    const bodGrantRes = await apiRequest('POST', `/api/documents/${createdSimDocId}/permissions`, {
      targetEmail: 'viewer@trustvault.local',
      userId: bobUserId,
      permissionLevel: 'READ',
      burnOnDownload: true
    }, ownerToken);

    record({
      persona: 'Owner (Alice)',
      flow: 'Ephemeral Sharing',
      action: 'Grant Burn-on-Download permission to Bob',
      expectedStatus: 201,
      actualStatus: bodGrantRes.status,
      passed: bodGrantRes.status === 201 || bodGrantRes.status === 200,
      notes: `Granted Burn-on-Download to Bob for ${createdSimDocId}`
    });
  }

  // --- PERSONA 3: BOB (AUTHORIZED VIEWER) ---
  console.log('\n--- SIMULATING PERSONA 3: BOB (AUTHORIZED VIEWER) ---');
  const viewerLogin = await apiRequest('POST', '/api/auth/login', {
    usernameOrEmail: 'viewer',
    password: 'Viewer@TrustVault2026!'
  });
  record({
    persona: 'Viewer (Bob)',
    flow: 'Authentication',
    action: 'Login via short username (viewer)',
    expectedStatus: 200,
    actualStatus: viewerLogin.status,
    passed: viewerLogin.status === 200 && !!viewerLogin.data?.token,
    notes: `Name: ${viewerLogin.data?.user?.name}, Role: ${viewerLogin.data?.user?.role}`
  });
  const viewerToken = viewerLogin.data?.token;

  // 3.1 Verify Viewer CANNOT Upload
  const viewerUploadRes = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: {
      'Cookie': viewerToken,
      'Content-Type': `multipart/form-data; boundary=${boundary}`
    },
    body: formPayload
  });
  record({
    persona: 'Viewer (Bob)',
    flow: 'Privilege Boundaries',
    action: 'Viewer attempts document upload',
    expectedStatus: 403,
    actualStatus: viewerUploadRes.status,
    passed: viewerUploadRes.status === 403,
    notes: `Viewer upload blocked with HTTP 403.`
  });

  // 3.2 Verify Viewer CANNOT Delegate/Share permissions
  if (msaDoc) {
    const viewerShareAttempt = await apiRequest('POST', `/api/documents/${msaDoc.id}/permissions`, {
      targetEmail: 'eve@trustvault.local',
      permissionLevel: 'READ'
    }, viewerToken);
    record({
      persona: 'Viewer (Bob)',
      flow: 'Privilege Boundaries',
      action: 'Viewer attempts to grant access to third party',
      expectedStatus: '403 or 404',
      actualStatus: viewerShareAttempt.status,
      passed: viewerShareAttempt.status === 403 || viewerShareAttempt.status === 404,
      notes: `Viewer re-sharing blocked with HTTP ${viewerShareAttempt.status}.`
    });
  }

  // 3.3 Test Burn-on-Download Flow:
  // First download -> 200 OK
  // Second download -> 404 Not Found (Auto-revoked!)
  if (createdSimDocId) {
    const firstBodDownload = await apiRequest('GET', `/api/documents/${createdSimDocId}/download`, null, viewerToken);
    record({
      persona: 'Viewer (Bob)',
      flow: 'Burn-on-Download (BOD)',
      action: 'First download of Burn-on-Download document',
      expectedStatus: 200,
      actualStatus: firstBodDownload.status,
      passed: firstBodDownload.status === 200,
      notes: `Received document bytes on first download.`
    });

    const secondBodDownload = await apiRequest('GET', `/api/documents/${createdSimDocId}/download`, null, viewerToken);
    record({
      persona: 'Viewer (Bob)',
      flow: 'Burn-on-Download (BOD)',
      action: 'Second download attempt of Burn-on-Download document',
      expectedStatus: 404,
      actualStatus: secondBodDownload.status,
      passed: secondBodDownload.status === 404,
      notes: `Immediate self-destruct confirmed (HTTP ${secondBodDownload.status}).`
    });
  }

  // 3.4 Verify Bob CANNOT see Alice's unshared Executive Comp doc
  const execCompDoc = ownerDocList.find((d: any) => d.originalFilename === 'Executive_Comp_Q3.pdf');
  if (execCompDoc) {
    const bobExecProbe = await apiRequest('GET', `/api/documents/${execCompDoc.id}`, null, viewerToken);
    record({
      persona: 'Viewer (Bob)',
      flow: 'Fail-Closed Information Barrier',
      action: 'Bob probes unshared Executive Comp document metadata',
      expectedStatus: 404,
      actualStatus: bobExecProbe.status,
      passed: bobExecProbe.status === 404,
      notes: `Received HTTP ${bobExecProbe.status} (Existence hidden from Bob).`
    });

    const bobExecDownload = await apiRequest('GET', `/api/documents/${execCompDoc.id}/download`, null, viewerToken);
    record({
      persona: 'Viewer (Bob)',
      flow: 'Fail-Closed Information Barrier',
      action: 'Bob probes unshared Executive Comp download stream',
      expectedStatus: 404,
      actualStatus: bobExecDownload.status,
      passed: bobExecDownload.status === 404,
      notes: `Received HTTP ${bobExecDownload.status} (Download blocked and existence hidden).`
    });
  }

  // --- PERSONA 4: EVE (ADVERSARY) ---
  console.log('\n--- SIMULATING PERSONA 4: EVE (ADVERSARY) ---');
  const eveLogin = await apiRequest('POST', '/api/auth/login', {
    usernameOrEmail: 'eve',
    password: 'Eve@TrustVault2026!'
  });
  record({
    persona: 'Adversary (Eve)',
    flow: 'Authentication',
    action: 'Login via short username (eve)',
    expectedStatus: 200,
    actualStatus: eveLogin.status,
    passed: eveLogin.status === 200 && !!eveLogin.data?.token,
    notes: `Name: ${eveLogin.data?.user?.name}, Role: ${eveLogin.data?.user?.role}`
  });
  const eveToken = eveLogin.data?.token;

  // 4.1 Eve sees 0 documents
  const eveDocs = await apiRequest('GET', '/api/documents', null, eveToken);
  const eveDocList = eveDocs.data?.documents || eveDocs.data || [];
  record({
    persona: 'Adversary (Eve)',
    flow: 'Tenancy Isolation',
    action: 'GET /api/documents (Zero-grant viewer)',
    expectedStatus: 200,
    actualStatus: eveDocs.status,
    passed: eveDocs.status === 200 && eveDocList.length === 0,
    notes: `Eve sees ${eveDocList.length} documents (Complete isolation).`
  });

  // 4.2 Cross-Tenant IDOR Download Probe by Eve
  if (msaDoc) {
    const eveIdorDownload = await apiRequest('GET', `/api/documents/${msaDoc.id}/download`, null, eveToken);
    record({
      persona: 'Adversary (Eve)',
      flow: 'CWE-639 IDOR Defense',
      action: `Eve probes private document IDOR download (${msaDoc.id})`,
      expectedStatus: 404,
      actualStatus: eveIdorDownload.status,
      passed: eveIdorDownload.status === 404,
      notes: `Received HTTP ${eveIdorDownload.status} (No 403 leakage).`
    });

    const eveIdorMetadata = await apiRequest('GET', `/api/documents/${msaDoc.id}`, null, eveToken);
    record({
      persona: 'Adversary (Eve)',
      flow: 'CWE-209 Existence Oracle Defense',
      action: `Eve probes private document metadata (${msaDoc.id})`,
      expectedStatus: 404,
      actualStatus: eveIdorMetadata.status,
      passed: eveIdorMetadata.status === 404,
      notes: `Received HTTP ${eveIdorMetadata.status} (Existence barrier intact).`
    });
  }

  // 4.3 Search query isolation
  const eveSearch = await apiRequest('GET', '/api/documents/search?q=Acme', null, eveToken);
  const eveSearchList = eveSearch.data?.documents || eveSearch.data || [];
  record({
    persona: 'Adversary (Eve)',
    flow: 'Search Isolation',
    action: 'Eve searches for "Acme"',
    expectedStatus: 200,
    actualStatus: eveSearch.status,
    passed: eveSearch.status === 200 && eveSearchList.length === 0,
    notes: `Search returned ${eveSearchList.length} results.`
  });

  // --- PERSONA 5: THREAT SCANNER & INPUT HARDENING ---
  console.log('\n--- SIMULATING THREAT SCANNER & INPUT HARDENING ---');
  // 5.1 Disguised Windows Executable (MZ bytes renamed .pdf)
  const mzBoundary = '----WebKitFormBoundaryMZ' + Date.now();
  const mzPayload = [
    `--${mzBoundary}`,
    'Content-Disposition: form-data; name="title"',
    '',
    'Weaponized MZ Payload',
    `--${mzBoundary}`,
    'Content-Disposition: form-data; name="file"; filename="invoice_malware.pdf"',
    'Content-Type: application/pdf',
    '',
    'MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00This is a Windows PE header disguised as PDF',
    `--${mzBoundary}--`
  ].join('\r\n');

  const peUploadRes = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: {
      'Cookie': ownerToken,
      'Content-Type': `multipart/form-data; boundary=${mzBoundary}`
    },
    body: mzPayload
  });
  record({
    persona: 'Threat Scanner',
    flow: 'Magic Byte Verification',
    action: 'Upload Windows PE executable disguised as .pdf',
    expectedStatus: 400,
    actualStatus: peUploadRes.status,
    passed: peUploadRes.status === 400,
    notes: `Disguised PE blocked with HTTP ${peUploadRes.status}.`
  });

  // 5.2 Weaponized PDF with /Launch Action
  const launchBoundary = '----WebKitFormBoundaryLaunch' + Date.now();
  const launchPdf = '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /Names << /JavaScript 3 0 R >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n3 0 obj\n<< /Type /Action /S /Launch /F (powershell.exe) >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000090 00000 n \n0000000140 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n210\n%%EOF\n';
  const launchPayload = [
    `--${launchBoundary}`,
    'Content-Disposition: form-data; name="title"',
    '',
    'Weaponized Launch PDF',
    `--${launchBoundary}`,
    'Content-Disposition: form-data; name="file"; filename="exploit_launch.pdf"',
    'Content-Type: application/pdf',
    '',
    launchPdf,
    `--${launchBoundary}--`
  ].join('\r\n');

  const launchUploadRes = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: {
      'Cookie': ownerToken,
      'Content-Type': `multipart/form-data; boundary=${launchBoundary}`
    },
    body: launchPayload
  });
  record({
    persona: 'Threat Scanner',
    flow: 'Heuristic Deep Inspection',
    action: 'Upload PDF containing /Launch OS execution action',
    expectedStatus: 400,
    actualStatus: launchUploadRes.status,
    passed: launchUploadRes.status === 400,
    notes: `Weaponized PDF blocked with HTTP ${launchUploadRes.status}.`
  });

  // 5.3 Probing Non-existent or Malformed UUID
  const invalidUuidProbe = await apiRequest('GET', '/api/documents/00000000-0000-0000-0000-000000000000', null, ownerToken);
  record({
    persona: 'Audit Robustness',
    flow: 'Existence Oracle & DB Constraint Robustness',
    action: 'Probe non-existent UUID in document route',
    expectedStatus: 404,
    actualStatus: invalidUuidProbe.status,
    passed: invalidUuidProbe.status === 404,
    notes: `Clean HTTP ${invalidUuidProbe.status} without server crash or FK violation.`
  });

  // 5.4 Timing attack parity check on login
  const t0 = Date.now();
  await apiRequest('POST', '/api/auth/login', {
    usernameOrEmail: 'nonexistent_user_probe@trustvault.local',
    password: 'Password123!'
  });
  const tNonExistent = Date.now() - t0;

  const t1 = Date.now();
  await apiRequest('POST', '/api/auth/login', {
    usernameOrEmail: 'admin@trustvault.local',
    password: 'WrongPassword123!'
  });
  const tRealUserWrongPass = Date.now() - t1;

  const timingDiff = Math.abs(tNonExistent - tRealUserWrongPass);
  record({
    persona: 'Crypto Defense',
    flow: 'Timing Attack Mitigation',
    action: 'Dummy bcrypt timing parity check',
    expectedStatus: 'Close execution times (< 400ms delta)',
    actualStatus: `Delta: ${timingDiff}ms (NonExistent: ${tNonExistent}ms, RealUser: ${tRealUserWrongPass}ms)`,
    passed: timingDiff < 400,
    notes: `Timing delta is ${timingDiff}ms.`
  });

  // --- SUMMARY OF RESULTS ---
  console.log('\n================================================================');
  console.log('SIMULATION RESULTS SUMMARY');
  console.log('================================================================');
  const total = reports.length;
  const passed = reports.filter(r => r.passed).length;
  const failed = reports.filter(r => !r.passed).length;
  console.log(`Total Scenarios: ${total}`);
  console.log(`Passed:          ${passed}`);
  console.log(`Failed / Issues: ${failed}`);

  if (failed > 0) {
    console.log('\nIdentified Issues:');
    reports.filter(r => !r.passed).forEach(r => {
      console.log(`- [${r.persona}] ${r.action}: Expected ${r.expectedStatus}, got ${r.actualStatus} (${r.bugOrIssue || r.notes})`);
    });
  }
}

runSimulation().catch(console.error);
