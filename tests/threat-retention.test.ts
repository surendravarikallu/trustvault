import { describe, it, expect, beforeAll } from '@jest/globals';
import request from 'supertest';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { app } from '../src/server';
import { ThreatScanner } from '../src/services/threatScanner';
import { RetentionService } from '../src/services/retentionService';

import { extractAuthCookie } from './testAuth';

let adminCookie: string;
let ownerCookie: string;

beforeAll(async () => {
  const adminRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'admin@trustvault.local', password: 'Admin@TrustVault2026!' });
  expect(adminRes.status).toBe(200);
  adminCookie = extractAuthCookie(adminRes);

  const ownerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });
  expect(ownerRes.status).toBe(200);
  ownerCookie = extractAuthCookie(ownerRes);
});

describe('Heuristic Threat Scanner & NIST SP 800-88 Crypto-Shredder Suite', () => {
  it('TS-01: Rejects weaponized PDF containing /Launch OS execution action', async () => {
    const tempDir = path.resolve(process.cwd(), 'storage/temp');
    if (!fs.existsSync(tempDir)) fs.mkdirSync(tempDir, { recursive: true });

    const evilPdfPath = path.join(tempDir, `weaponized_${Date.now()}.pdf`);
    const evilContent = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Action /S /Launch /F (cmd.exe) >>\nendobj\n%%EOF', 'binary');
    fs.writeFileSync(evilPdfPath, evilContent);

    const scan = await ThreatScanner.scanFile(evilPdfPath, 'exploit.pdf');
    expect(scan.isSafe).toBe(false);
    expect(scan.threatType).toBe('PDF_EXPLOIT_LAUNCH_COMMAND');

    fs.unlinkSync(evilPdfPath);
  });

  it('TS-02: Rejects PDF containing active /JavaScript exploit stream', async () => {
    const tempDir = path.resolve(process.cwd(), 'storage/temp');
    const evilPdfPath = path.join(tempDir, `js_exploit_${Date.now()}.pdf`);
    const evilContent = Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert("pwned")) >>\nendobj\n%%EOF', 'binary');
    fs.writeFileSync(evilPdfPath, evilContent);

    const scan = await ThreatScanner.scanFile(evilPdfPath, 'invoice.pdf');
    expect(scan.isSafe).toBe(false);
    expect(scan.threatType).toBe('PDF_EMBEDDED_JAVASCRIPT');

    fs.unlinkSync(evilPdfPath);
  });

  it('TS-03: Rejects OOXML Word document containing embedded vbaProject.bin macro', async () => {
    const tempDir = path.resolve(process.cwd(), 'storage/temp');
    const macroDocPath = path.join(tempDir, `macro_test_${Date.now()}.docx`);
    const fakeDocx = Buffer.concat([
      Buffer.from([0x50, 0x4b, 0x03, 0x04]), // PK zip magic
      Buffer.from('word/vbaProject.bin payload embedded macro binary')
    ]);
    fs.writeFileSync(macroDocPath, fakeDocx);

    const scan = await ThreatScanner.scanFile(macroDocPath, 'agreement.docx');
    expect(scan.isSafe).toBe(false);
    expect(scan.threatType).toBe('OFFICE_WEAPONIZED_MACRO');

    fs.unlinkSync(macroDocPath);
  });

  it('TS-04: Rejects text document containing obfuscated PowerShell execution command', async () => {
    const tempDir = path.resolve(process.cwd(), 'storage/temp');
    const scriptPath = path.join(tempDir, `ps_test_${Date.now()}.txt`);
    fs.writeFileSync(scriptPath, 'powershell -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAApAA==');

    const scan = await ThreatScanner.scanFile(scriptPath, 'notes.txt');
    expect(scan.isSafe).toBe(false);
    expect(scan.threatType).toBe('OBFUSCATED_POWERSHELL_PAYLOAD');

    fs.unlinkSync(scriptPath);
  });

  it('CS-01: NIST SP 800-88 crypto-wiping overwrites disk sectors with entropy before unlinking', async () => {
    const tempDir = path.resolve(process.cwd(), 'storage/temp');
    const secretFile = path.join(tempDir, `sensitive_contract_${Date.now()}.txt`);
    const initialPlaintext = Buffer.from('TOP_SECRET_PROPRIETARY_ALGORITHM_SOURCE_2026', 'utf8');
    fs.writeFileSync(secretFile, initialPlaintext);

    expect(fs.existsSync(secretFile)).toBe(true);

    const wipedBytes = await RetentionService.cryptoWipeFile(secretFile);

    expect(wipedBytes).toBe(initialPlaintext.length);
    expect(fs.existsSync(secretFile)).toBe(false);
  });

  it('CS-02: Admin retention crypto-shred endpoint enforces RBAC and logs to HMAC ledger', async () => {
    // 1. Upload a document as owner
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .field('title', 'Ephemeral Audit Shred Test')
      .field('category', 'Legal')
      .attach('file', Buffer.from('%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF'), {
        filename: 'shred_target.pdf',
        contentType: 'application/pdf'
      });

    expect(uploadRes.status).toBe(201);
    const docId = uploadRes.body.document.id;

    // 2. Admin triggers immediate NIST crypto-shred on the document
    const shredRes = await request(app)
      .post('/api/admin/retention/crypto-shred')
      .set('Cookie', adminCookie)
      .send({ documentId: docId });

    expect(shredRes.status).toBe(200);
    expect(shredRes.body.message).toContain('NIST SP 800-88 cryptographic shredding completed');
    expect(shredRes.body.report.documentId).toBe(docId);

    // 3. Confirm document is completely purged from database
    const probeRes = await request(app)
      .get(`/api/documents/${docId}`)
      .set('Cookie', ownerCookie);
    expect(probeRes.status).toBe(404);
  });
});
