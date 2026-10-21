import { prisma } from '../src/prisma';
import { StorageService } from '../src/services/storageService';
import { verifyAuditChain } from '../src/dal/auditDal';
import fs from 'fs';
import path from 'path';

const BASE_URL = process.env.BASE_URL || 'http://127.0.0.1:7777';

interface SimulationStepResult {
  category: string;
  testCase: string;
  actor: string;
  status: 'PASS' | 'FAIL';
  httpStatus: number;
  details: string;
}

const results: SimulationStepResult[] = [];

async function login(email: string, password: string): Promise<string> {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Login failed for ${email} (${res.status}): ${text}`);
  }

  const setCookie = res.headers.get('set-cookie');
  if (!setCookie) throw new Error(`No cookie returned for ${email}`);
  return setCookie.split(';')[0];
}

async function uploadMultipart(
  cookie: string,
  title: string,
  filename: string,
  contentBuffer: Buffer,
  category = 'Legal'
): Promise<{ status: number; body: any }> {
  const boundary = '----TrustVaultSimulationBoundary' + Math.random().toString(36).substring(2);

  let pre = '';
  pre += `--${boundary}\r\nContent-Disposition: form-data; name="title"\r\n\r\n${title}\r\n`;
  pre += `--${boundary}\r\nContent-Disposition: form-data; name="category"\r\n\r\n${category}\r\n`;
  pre += `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`;

  const preBuf = Buffer.from(pre, 'utf-8');
  const postBuf = Buffer.from(`\r\n--${boundary}--\r\n`, 'utf-8');
  const body = Buffer.concat([preBuf, contentBuffer, postBuf]);

  const res = await fetch(`${BASE_URL}/api/documents`, {
    method: 'POST',
    headers: {
      'Cookie': cookie,
      'Content-Type': `multipart/form-data; boundary=${boundary}`
    },
    body
  });

  const raw = await res.text();
  let parsed: any = null;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = raw;
  }

  return { status: res.status, body: parsed };
}

async function requestApi(
  url: string,
  method = 'GET',
  cookie?: string,
  data?: any
): Promise<{ status: number; body: any }> {
  const headers: Record<string, string> = {};
  if (cookie) headers['Cookie'] = cookie;
  if (data && typeof data === 'object') headers['Content-Type'] = 'application/json';

  const res = await fetch(url, {
    method,
    headers,
    body: data ? (typeof data === 'string' ? data : JSON.stringify(data)) : undefined
  });

  const raw = await res.text();
  let parsed: any;
  try {
    parsed = JSON.parse(raw);
  } catch {
    parsed = raw;
  }
  return { status: res.status, body: parsed };
}

async function runCompleteSimulation() {
  console.log(`========================================================================`);
  console.log(` TRUSTVAULT COMPLETE ZERO-TRUST END-TO-END USER & SECURITY SIMULATION`);
  console.log(` Target Server: ${BASE_URL}`);
  console.log(` Timestamp: ${new Date().toISOString()}`);
  console.log(`========================================================================\n`);

  // Ensure base accounts exist
  const adminCookie = await login('admin@trustvault.local', 'Admin@TrustVault2026!');
  const ownerCookie = await login('owner@trustvault.local', 'Owner@TrustVault2026!');
  const eveCookie = await login('eve@trustvault.local', 'Eve@TrustVault2026!');

  // =========================================================================
  // SECTION 1: ADMIN USER LIFECYCLE & GOVERNANCE SIMULATION
  // =========================================================================
  console.log('>>> [1/4] Running Admin Governance & Identity Lifecycle Simulation...');

  // 1.1 Create User
  const testUserEmail = `sim_analyst_${Date.now()}@trustvault.local`;
  const initialPassword = 'Analyst@TrustVault2026!';
  const createRes = await requestApi(`${BASE_URL}/api/admin/users`, 'POST', adminCookie, {
    name: 'Simulation Analyst',
    email: testUserEmail,
    password: initialPassword,
    role: 'VIEWER'
  });

  const createdUserId = createRes.body?.user?.id;
  results.push({
    category: 'Admin Governance',
    testCase: 'User Provisioning via Admin API',
    actor: 'Admin',
    status: createRes.status === 201 && createdUserId ? 'PASS' : 'FAIL',
    httpStatus: createRes.status,
    details: `Created user ${testUserEmail} with role VIEWER (ID: ${createdUserId})`
  });

  // Verify created user can log in
  let analystCookie = '';
  try {
    analystCookie = await login(testUserEmail, initialPassword);
    results.push({
      category: 'Admin Governance',
      testCase: 'Newly Created User Login Validation',
      actor: testUserEmail,
      status: 'PASS',
      httpStatus: 200,
      details: 'User successfully authenticated and received secure __Host- cookie'
    });
  } catch (err: any) {
    results.push({
      category: 'Admin Governance',
      testCase: 'Newly Created User Login Validation',
      actor: testUserEmail,
      status: 'FAIL',
      httpStatus: 401,
      details: err.message
    });
  }

  // 1.2 Assign / Change Role
  const roleRes = await requestApi(
    `${BASE_URL}/api/admin/users/${createdUserId}/role`,
    'PATCH',
    adminCookie,
    { role: 'OWNER' }
  );

  results.push({
    category: 'Admin Governance',
    testCase: 'Role Mutation & Token Invalidation (VIEWER -> OWNER)',
    actor: 'Admin',
    status: roleRes.status === 200 ? 'PASS' : 'FAIL',
    httpStatus: roleRes.status,
    details: `Promoted role to OWNER. Token version bumped to ${roleRes.body?.user?.tokenVersion}`
  });

  // 1.3 Verify old session was invalidated by tokenVersion bump (L-01)
  const probeOldSession = await requestApi(`${BASE_URL}/api/auth/me`, 'GET', analystCookie);
  results.push({
    category: 'Admin Governance',
    testCase: 'Immediate Session Invalidation on Role Change (L-01)',
    actor: testUserEmail,
    status: probeOldSession.status === 401 ? 'PASS' : 'FAIL',
    httpStatus: probeOldSession.status,
    details: 'Old session token immediately rejected with 401 following role modification'
  });

  // 1.4 Admin Reset Password
  const newPassword = 'NewAnalystPassword@2026!';
  const resetPassRes = await requestApi(
    `${BASE_URL}/api/admin/users/${createdUserId}/reset-password`,
    'POST',
    adminCookie,
    { newPassword }
  );

  results.push({
    category: 'Admin Governance',
    testCase: 'Admin Emergency Password Reset',
    actor: 'Admin',
    status: resetPassRes.status === 200 ? 'PASS' : 'FAIL',
    httpStatus: resetPassRes.status,
    details: 'Password updated and previous sessions severed'
  });

  // Re-login with new password
  analystCookie = await login(testUserEmail, newPassword);

  // 1.5 2FA Emergency Reset
  const reset2faRes = await requestApi(
    `${BASE_URL}/api/admin/users/${createdUserId}/reset-2fa`,
    'POST',
    adminCookie
  );

  results.push({
    category: 'Admin Governance',
    testCase: 'Admin Emergency 2FA Reset (Account Recovery)',
    actor: 'Admin',
    status: reset2faRes.status === 200 ? 'PASS' : 'FAIL',
    httpStatus: reset2faRes.status,
    details: 'MFA secrets wiped and tokenVersion incremented'
  });

  // 1.6 Deactivate User
  const deactRes = await requestApi(
    `${BASE_URL}/api/admin/users/${createdUserId}/deactivate`,
    'POST',
    adminCookie
  );

  results.push({
    category: 'Admin Governance',
    testCase: 'Administrative User Deactivation',
    actor: 'Admin',
    status: deactRes.status === 200 ? 'PASS' : 'FAIL',
    httpStatus: deactRes.status,
    details: 'User marked isActive=false'
  });

  // Verify deactivated user cannot log in
  let deactLoginBlocked = false;
  try {
    await login(testUserEmail, newPassword);
  } catch (err: any) {
    deactLoginBlocked = true;
  }

  results.push({
    category: 'Admin Governance',
    testCase: 'Deactivated User Login Blocked',
    actor: testUserEmail,
    status: deactLoginBlocked ? 'PASS' : 'FAIL',
    httpStatus: 401,
    details: 'Deactivated user blocked from authentication'
  });

  // =========================================================================
  // SECTION 2: MALICIOUS FILE ATTACKS VS LEGITIMATE UPLOADS
  // =========================================================================
  console.log('\n>>> [2/4] Running File Upload Hardening & Exploit Detection Simulation...');

  // 2.1 Legitimate PDF Upload
  const validPdfBytes = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Title (Legitimate Corporate Audit Policy) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF');
  const validUploadRes = await uploadMultipart(
    ownerCookie,
    'Legitimate Corporate Audit Policy',
    'audit_policy_2026.pdf',
    validPdfBytes
  );

  const legitimateDocId = validUploadRes.body?.document?.id || validUploadRes.body?.id;
  results.push({
    category: 'Upload Defense',
    testCase: 'Legitimate PDF Document Upload',
    actor: 'Owner (Alice)',
    status: validUploadRes.status === 201 && legitimateDocId ? 'PASS' : 'FAIL',
    httpStatus: validUploadRes.status,
    details: `Stored securely in vault (Doc ID: ${legitimateDocId})`
  });

  // 2.2 Attack: Disguised PE Executable (.exe disguised as .pdf)
  // MZ header is 0x4D, 0x5A
  const peExeDisguisedAsPdf = Buffer.from('MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00\xb8\x00\x00\x00This is a malicious PE executable disguised as a pdf document!');
  const peAttackRes = await uploadMultipart(
    ownerCookie,
    'Malicious Disguised Executable',
    'invoice.pdf',
    peExeDisguisedAsPdf
  );

  results.push({
    category: 'Upload Defense',
    testCase: 'Disguised Executable (MZ PE binary disguised as .pdf)',
    actor: 'Adversary',
    status: peAttackRes.status === 400 && String(peAttackRes.body?.error).includes('Disguised Windows executable') ? 'PASS' : 'FAIL',
    httpStatus: peAttackRes.status,
    details: `Blocked with 400: ${peAttackRes.body?.error}`
  });

  // 2.3 Attack: Weaponized PDF Exploit containing /Launch OS Execution Action
  const pdfWithLaunchExploit = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /Launch /F (cmd.exe) /P (/c calc.exe) >> >>\nendobj\n%%EOF'
  );
  const launchAttackRes = await uploadMultipart(
    ownerCookie,
    'Weaponized PDF Launch Exploit',
    'exploit_launch.pdf',
    pdfWithLaunchExploit
  );

  results.push({
    category: 'Upload Defense',
    testCase: 'Weaponized PDF Exploit (/Launch OS Command Action)',
    actor: 'Adversary',
    status: launchAttackRes.status === 400 && String(launchAttackRes.body?.error).includes('/Launch') ? 'PASS' : 'FAIL',
    httpStatus: launchAttackRes.status,
    details: `Blocked with 400: ${launchAttackRes.body?.error}`
  });

  // 2.4 Attack: Weaponized PDF Exploit containing /JavaScript Stream
  const pdfWithJsExploit = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert("Pwned");) >>\nendobj\n%%EOF'
  );
  const jsAttackRes = await uploadMultipart(
    ownerCookie,
    'Weaponized PDF JavaScript Exploit',
    'exploit_js.pdf',
    pdfWithJsExploit
  );

  results.push({
    category: 'Upload Defense',
    testCase: 'Weaponized PDF Exploit (/JavaScript Scripting Stream)',
    actor: 'Adversary',
    status: jsAttackRes.status === 400 && String(jsAttackRes.body?.error).includes('/JavaScript') ? 'PASS' : 'FAIL',
    httpStatus: jsAttackRes.status,
    details: `Blocked with 400: ${jsAttackRes.body?.error}`
  });

  // 2.5 Attack: Obfuscated PowerShell Infiltration Script
  const obfuscatedPs = Buffer.from('powershell -encodedcommand SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==');
  const psAttackRes = await uploadMultipart(
    ownerCookie,
    'Obfuscated PowerShell Script',
    'network_tool.txt',
    obfuscatedPs
  );

  results.push({
    category: 'Upload Defense',
    testCase: 'Obfuscated PowerShell Command Infiltration',
    actor: 'Adversary',
    status: psAttackRes.status === 400 && String(psAttackRes.body?.error).includes('PowerShell') ? 'PASS' : 'FAIL',
    httpStatus: psAttackRes.status,
    details: `Blocked with 400: ${psAttackRes.body?.error}`
  });

  // 2.6 Attack: Unauthorized File Extension (.sh shell script)
  const shellScript = Buffer.from('#!/bin/bash\nrm -rf /\n');
  const shAttackRes = await uploadMultipart(
    ownerCookie,
    'Shell Script',
    'exploit.sh',
    shellScript
  );

  results.push({
    category: 'Upload Defense',
    testCase: 'Unauthorized File Extension (.sh / .exe / .html rejection)',
    actor: 'Adversary',
    status: shAttackRes.status === 400 ? 'PASS' : 'FAIL',
    httpStatus: shAttackRes.status,
    details: `Blocked with 400: ${shAttackRes.body?.error}`
  });

  // Verify that NONE of the malicious files were written to storage or database
  const countDocs = await prisma.document.count({
    where: {
      OR: [
        { originalFilename: 'invoice.pdf' },
        { originalFilename: 'exploit_launch.pdf' },
        { originalFilename: 'exploit_js.pdf' },
        { originalFilename: 'network_tool.txt' },
        { originalFilename: 'exploit.sh' }
      ]
    }
  });

  results.push({
    category: 'Upload Defense',
    testCase: 'Database Isolation (Zero Malicious Records Stored)',
    actor: 'Database Verification',
    status: countDocs === 0 ? 'PASS' : 'FAIL',
    httpStatus: 200,
    details: `Verified: ${countDocs} malicious documents found in database (Must be 0)`
  });

  // =========================================================================
  // SECTION 3: MULTI-USER PERMISSIONS, ROLES & ISOLATION SIMULATION
  // =========================================================================
  console.log('\n>>> [3/4] Running Multi-User Authorization & Isolation Simulation...');

  // 3.1 Viewer cannot upload documents (L-05)
  const viewerUploadRes = await uploadMultipart(
    eveCookie,
    'Viewer Unauthorized Upload',
    'viewer_file.txt',
    Buffer.from('Unauthorized text content')
  );

  results.push({
    category: 'Access Control',
    testCase: 'Viewer Upload Barrier (L-05)',
    actor: 'Viewer (Eve)',
    status: viewerUploadRes.status === 403 ? 'PASS' : 'FAIL',
    httpStatus: viewerUploadRes.status,
    details: `Correctly denied with 403: ${viewerUploadRes.body?.error}`
  });

  // 3.2 Share Alice's document with Bob
  const bobEmail = 'bob.grantee@trustvault.local';
  let bobUser = await prisma.user.findUnique({ where: { email: bobEmail } });
  if (!bobUser) {
    const bcrypt = await import('bcrypt');
    bobUser = await prisma.user.create({
      data: {
        email: bobEmail,
        name: 'Bob Grantee',
        passwordHash: await bcrypt.hash('Bob@TrustVault2026!', 10),
        role: 'VIEWER'
      }
    });
  }

  const shareRes = await requestApi(
    `${BASE_URL}/api/documents/${legitimateDocId}/permissions`,
    'POST',
    ownerCookie,
    {
      targetEmail: bobEmail,
      permissionLevel: 'READ'
    }
  );

  results.push({
    category: 'Access Control',
    testCase: 'Owner Grants Document Read Permission',
    actor: 'Owner (Alice)',
    status: shareRes.status === 200 || shareRes.status === 201 ? 'PASS' : 'FAIL',
    httpStatus: shareRes.status,
    details: `Granted READ access on document ${legitimateDocId} to ${bobEmail}`
  });

  // 3.3 Bob logs in and downloads document
  const bobCookie = await login(bobEmail, 'Bob@TrustVault2026!');
  const bobDownloadRes = await requestApi(
    `${BASE_URL}/api/documents/${legitimateDocId}/download`,
    'GET',
    bobCookie
  );

  results.push({
    category: 'Access Control',
    testCase: 'Authorized Grantee Download (Bob)',
    actor: 'Grantee (Bob)',
    status: bobDownloadRes.status === 200 ? 'PASS' : 'FAIL',
    httpStatus: bobDownloadRes.status,
    details: 'Authorized grantee successfully downloaded document content (HTTP 200)'
  });

  // 3.4 Eve probes Alice's document (unshared)
  const eveDownloadProbe = await requestApi(
    `${BASE_URL}/api/documents/${legitimateDocId}/download`,
    'GET',
    eveCookie
  );

  const fakeId = '00000000-0000-0000-0000-000000000000';
  const eveFakeProbe = await requestApi(
    `${BASE_URL}/api/documents/${fakeId}/download`,
    'GET',
    eveCookie
  );

  const identical404 = eveDownloadProbe.status === 404 &&
    eveFakeProbe.status === 404 &&
    JSON.stringify(eveDownloadProbe.body) === JSON.stringify(eveFakeProbe.body);

  results.push({
    category: 'Access Control',
    testCase: 'Unshared Adversary Download Probe (No Existence Oracle)',
    actor: 'Adversary (Eve)',
    status: identical404 ? 'PASS' : 'FAIL',
    httpStatus: eveDownloadProbe.status,
    details: `Returned identical 404: ${JSON.stringify(eveDownloadProbe.body)} (No existence oracle)`
  });

  // =========================================================================
  // SECTION 4: AUDIT LEDGER CRYPTOGRAPHIC VERIFICATION
  // =========================================================================
  console.log('\n>>> [4/4] Verifying Cryptographic Audit Ledger & Chain Integrity...');

  const auditVerifyRes = await verifyAuditChain();
  results.push({
    category: 'Audit Immutability',
    testCase: 'HMAC-SHA256 Cryptographic Chain Continuous Integrity',
    actor: 'Audit Verifier',
    status: auditVerifyRes.valid ? 'PASS' : 'FAIL',
    httpStatus: 200,
    details: `Chain Status: ${auditVerifyRes.valid ? 'VALID' : 'CORRUPTED'}, Height: ${auditVerifyRes.headSequence}, Head: ${auditVerifyRes.headHash?.substring(0, 16)}...`
  });

  results.push({
    category: 'Audit Immutability',
    testCase: 'External Anchor Verification Match',
    actor: 'Audit Verifier',
    status: auditVerifyRes.anchorMatched ? 'PASS' : 'FAIL',
    httpStatus: 200,
    details: `Anchor Matched: ${auditVerifyRes.anchorMatched}`
  });

  // Query recent audit logs to verify captured events
  const recentLogs = await prisma.auditLog.findMany({
    take: 15,
    orderBy: { sequenceNumber: 'desc' },
    select: {
      sequenceNumber: true,
      action: true,
      status: true,
      userEmail: true,
      details: true,
      hash: true
    }
  });

  // Clean up test documents
  await prisma.documentPermission.deleteMany({ where: { documentId: legitimateDocId } });
  await prisma.document.delete({ where: { id: legitimateDocId } });

  // Print Summary Table
  console.log('\n=========================================================================================================');
  console.log(' SIMULATION TEST REPORT & EVIDENCE MATRIX');
  console.log('=========================================================================================================');
  console.log('| Category | Test Case | Actor | HTTP | Status | Details |');
  console.log('| :--- | :--- | :--- | :---: | :---: | :--- |');
  for (const r of results) {
    console.log(`| ${r.category} | ${r.testCase} | ${r.actor} | ${r.httpStatus} | **${r.status}** | ${r.details} |`);
  }
  console.log('=========================================================================================================\n');

  console.log('--- RECENT AUDIT LEDGER EVENTS CAPTURED ---');
  for (const log of recentLogs) {
    console.log(`[Seq #${log.sequenceNumber}] ${log.action} [${log.status}] (${log.userEmail}): ${log.details.slice(0, 80)}...`);
  }
  console.log('=========================================================================================================\n');
}

runCompleteSimulation()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('Simulation Failed:', err);
    process.exit(1);
  });
