import { describe, it, expect, beforeAll } from '@jest/globals';
import request from 'supertest';
import { app } from '../src/server';

let ownerToken: string;

beforeAll(async () => {
  const ownerRes = await request(app)
    .post('/api/auth/login')
    .send({ email: 'owner@trustvault.local', password: 'Owner@TrustVault2026!' });
  ownerToken = ownerRes.body.token;
});

describe('Upload Hardening, Storage Lifecycle & Search Bounding Suite', () => {
  it('UPL-01: Rejects disguised Windows PE executables (MZ magic bytes) even with .pdf extension', async () => {
    const maliciousPayload = Buffer.from('MZ\x90\x00\x03\x00\x00\x00MaliciousPayloadBinaryDataHere');

    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
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
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Shell Script Document')
      .field('category', 'General')
      .attach('file', scriptPayload, 'script.sh');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('not in the permitted whitelist');
  });

  it('UPL-03: Rejects mismatched extension and magic bytes (e.g. plain text named as .docx)', async () => {
    const fakeDocxPayload = Buffer.from('This is plain text, not a valid ZIP/OOXML archive');

    const res = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Corrupted Document')
      .field('category', 'General')
      .attach('file', fakeDocxPayload, 'financial_report.docx');

    expect(res.status).toBe(400);
    expect(res.body.error).toContain('lacks valid ZIP/OOXML header');
  });

  it('UPL-04: Replacing document content preserves historical version record in DocumentVersion', async () => {
    // 1. Upload initial version
    const v1Content = Buffer.from('%PDF-1.4\nVersion 1 Content\n%%EOF');
    const uploadRes = await request(app)
      .post('/api/documents')
      .set('Authorization', `Bearer ${ownerToken}`)
      .field('title', 'Version Retention Document')
      .field('category', 'General')
      .attach('file', v1Content, 'doc_v1.pdf');

    expect(uploadRes.status).toBe(201);
    const docId = uploadRes.body.document.id;

    // 2. Upload replacement version
    const v2Content = Buffer.from('%PDF-1.4\nVersion 2 Content Updated\n%%EOF');
    const replaceRes = await request(app)
      .put(`/api/documents/${docId}`)
      .set('Authorization', `Bearer ${ownerToken}`)
      .attach('file', v2Content, 'doc_v2.pdf');

    expect(replaceRes.status).toBe(200);

    // 3. Query versions endpoint (Owner-only)
    const versionsRes = await request(app)
      .get(`/api/documents/${docId}/versions`)
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(versionsRes.status).toBe(200);
    expect(versionsRes.body.versions.length).toBeGreaterThanOrEqual(1);
    expect(versionsRes.body.versions[0].versionNumber).toBe(1);
  });

  it('UPL-05: Broad search queries enforce bounded upper limit (take: 100) preventing heap exhaustion', async () => {
    const searchRes = await request(app)
      .get('/api/documents/search')
      .set('Authorization', `Bearer ${ownerToken}`);

    expect(searchRes.status).toBe(200);
    expect(Array.isArray(searchRes.body.documents)).toBe(true);
    // Upper boundary ceiling of 100 items
    expect(searchRes.body.documents.length).toBeLessThanOrEqual(100);
  });
});
