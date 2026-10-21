import { describe, it, expect, beforeAll } from '@jest/globals';
import { AuditStatus } from '@prisma/client';
import { prisma } from '../src/prisma';
import { logAuditEvent, verifyAuditChain } from '../src/services/auditService';
import { exportAuditAnchor } from '../src/utils/auditAnchor';

describe('Cryptographic Audit Ledger Verification Suite', () => {
  it('L-10 & L-14: Successfully logs sequential audit events with valid HMAC chain', async () => {
    const hash1 = await logAuditEvent({
      action: 'TEST_ACTION_ALPHA',
      userId: 'test-user-1',
      userEmail: 'user1@trustvault.local',
      status: AuditStatus.SUCCESS,
      ipAddress: '127.0.0.1',
      userAgent: 'Jest Test Suite',
      details: 'Audit verification test alpha'
    });

    expect(hash1).toBeDefined();
    expect(hash1.length).toBe(64); // SHA-256 hex string length

    const hash2 = await logAuditEvent({
      action: 'TEST_ACTION_BETA',
      userId: 'test-user-2',
      userEmail: 'user2@trustvault.local',
      status: AuditStatus.SUCCESS,
      ipAddress: '127.0.0.1',
      userAgent: 'Jest Test Suite',
      details: 'Audit verification test beta'
    });

    expect(hash2).toBeDefined();
    expect(hash2.length).toBe(64);

    const verification = await verifyAuditChain();
    expect(verification.valid).toBe(true);
    expect(verification.totalRecords).toBeGreaterThanOrEqual(2);
  });

  it('L-13: Detects audit tail truncation when external anchor exceeds DB head', async () => {
    const verification = await verifyAuditChain();
    expect(verification.valid).toBe(true);

    const currentHeadSeq = BigInt(verification.headSequence || '1');
    const fakeFutureSeq = currentHeadSeq + 5n;

    // Export an anchor referencing a sequence higher than what exists in the DB
    await exportAuditAnchor(fakeFutureSeq, 'fakeheadhash1234567890abcdef1234567890abcdef1234567890abcdef1234', new Date());

    const tamperedVerification = await verifyAuditChain();
    expect(tamperedVerification.valid).toBe(false);
    expect(tamperedVerification.error).toContain('Audit tail truncation detected');

    // Restore anchor to current head
    await exportAuditAnchor(currentHeadSeq, verification.headHash || '', new Date());
    const restoredVerification = await verifyAuditChain();
    expect(restoredVerification.valid).toBe(true);
  });
});
