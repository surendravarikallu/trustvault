import { describe, it, expect, beforeAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../src/server';

let ownerCookie: string;

beforeAll(async () => {
  const ownerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });
  const setCookie = ownerRes.headers['set-cookie'];
  ownerCookie = Array.isArray(setCookie) ? setCookie[0].split(';')[0] : setCookie.split(';')[0];
});

describe('Upload Hardening, Storage Lifecycle & Search Bounding Suite', () => {
  it('UPL-01: Rejects disguised Windows PE executables (MZ magic bytes) even with .pdf extension', async () => {
    const maliciousPayload = Buffer.from('MZ\x90\x00\x03\x00\x00\x00MaliciousPayloadBinaryDataHere');

    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .field('title', 'Disguised Executable')
      .field('category', 'Legal')
      .attach('file', maliciousPayload, 'innocent_contract.pdf');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('Disguised Windows executable');
  });

  it('UPL-02: Rejects unauthorized file extensions (.sh, .exe, .html) not in whitelist', async () => {
    const scriptPayload = Buffer.from('#!/bin/bash\necho "exploit"\n');

    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .field('title', 'Shell Script Document')
      .field('category', 'General')
      .attach('file', scriptPayload, 'script.sh');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('not in the permitted whitelist');
  });

  it('UPL-03: Rejects mismatched extension and magic bytes (e.g. plain text named as .pdf)', async () => {
    const fakePdfPayload = Buffer.from('This is plain text, not a valid %PDF document');

    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .field('title', 'Corrupted Document')
      .field('category', 'General')
      .attach('file', fakePdfPayload, 'financial_report.pdf');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('lacks valid %PDF header');
  });

  it('UPL-03b: Rejects zip-based document extensions (.docx, .xlsx) removed from whitelist', async () => {
    const docxPayload = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]);

    const res = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .field('title', 'Office Document')
      .field('category', 'General')
      .attach('file', docxPayload, 'financial_report.docx');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('not in the permitted whitelist');
  });

  it('UPL-04: Replacing document content preserves historical version record in DocumentVersion', async () => {
    // 1. Upload initial version
    const v1Content = Buffer.from('%PDF-1.4\nVersion 1 Content\n%%EOF');
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Cookie', ownerCookie)
      .field('title', 'Version Retention Document')
      .field('category', 'General')
      .attach('file', v1Content, 'doc_v1.pdf');

    expect(uploadRes.status).toBe(201);
    const docId = uploadRes.body.document.id;

    // 2. Upload replacement version
    const v2Content = Buffer.from('%PDF-1.4\nVersion 2 Content Updated\n%%EOF');
    const replaceRes = await request(app)
      .put(`/api/documents/${docId}`)
      .set('Cookie', ownerCookie)
      .attach('file', v2Content, 'doc_v2.pdf');

    expect(replaceRes.status).toBe(200);

    // 3. Query versions endpoint (Owner-only)
    const versionsRes = await request(app)
      .get(`/api/documents/${docId}/versions`)
      .set('Cookie', ownerCookie);

    expect(versionsRes.status).toBe(200);
    expect(versionsRes.body.versions.length).toBeGreaterThanOrEqual(1);
    expect(versionsRes.body.versions[0].versionNumber).toBe(1);
  });

  it('UPL-05: Broad search queries enforce bounded upper limit (take: 100) preventing heap exhaustion', async () => {
    const searchRes = await request(app)
      .get('/api/documents/search')
      .set('Cookie', ownerCookie);

    expect(searchRes.status).toBe(200);
    expect(Array.isArray(searchRes.body.documents)).toBe(true);
    // Upper boundary ceiling of 100 items
    expect(searchRes.body.documents.length).toBeLessThanOrEqual(100);
  });
});
