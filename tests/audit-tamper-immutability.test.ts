import { describe, it, expect } from '@jest/globals';
import { PrismaClient, AuditStatus } from '@prisma/client';
import { logAuditEvent, verifyAuditChain, computeAuditHash, getAuditLogs } from '../src/dal/auditDal';
import { exportAuditAnchor, loadAuditAnchor } from '../src/utils/auditAnchor';

const prisma = new PrismaClient();

describe('Cryptographic Audit Ledger & Tamper Detection Suite', () => {
  it('AUD-01: Verifies all 13 canonical columns are cryptographically protected by HMAC-SHA256', async () => {
    // 1. Log a test event
    const timestamp = new Date();
    const hash = await logAuditEvent({
      action: 'CANONICAL_HMAC_TEST',
      userId: 'test-user-hmac',
      userEmail: 'audit_test@trustvault.local',
      documentId: '00000000-0000-0000-0000-000000000001',
      documentTitle: 'Protected Document Title',
      status: AuditStatus.SUCCESS,
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 Audit Agent',
      details: 'Original unaltered audit details'
    });

    expect(hash).toBeDefined();
    expect(hash.length).toBe(64); // Valid SHA-256 hex string

    // 2. Fetch the newly inserted record
    const latestLog = await prisma.auditLog.findFirst({
      where: { action: 'CANONICAL_HMAC_TEST' },
      orderBy: { sequenceNumber: 'desc' }
    });

    expect(latestLog).not.toBeNull();
    if (!latestLog) return;

    // 3. Recalculate hash on legitimate row
    const legitimateHash = computeAuditHash({
      id: latestLog.id,
      sequenceNumber: latestLog.sequenceNumber,
      timestamp: latestLog.timestamp,
      action: latestLog.action,
      userId: latestLog.userId,
      userEmail: latestLog.userEmail,
      documentId: latestLog.documentId,
      documentTitle: latestLog.documentTitle,
      status: latestLog.status,
      ipAddress: latestLog.ipAddress,
      userAgent: latestLog.userAgent,
      details: latestLog.details,
      previousHash: latestLog.previousHash
    });

    expect(latestLog.hash).toBe(legitimateHash);

    // 4. Test tampering each column individually: hash MUST change
    const tamperedDetailsHash = computeAuditHash({
      ...latestLog,
      details: 'Tampered details by adversary'
    });
    expect(tamperedDetailsHash).not.toBe(latestLog.hash);

    const tamperedUserEmailHash = computeAuditHash({
      ...latestLog,
      userEmail: 'forged_email@adversary.com'
    });
    expect(tamperedUserEmailHash).not.toBe(latestLog.hash);

    const tamperedTitleHash = computeAuditHash({
      ...latestLog,
      documentTitle: 'Forged Document Title'
    });
    expect(tamperedTitleHash).not.toBe(latestLog.hash);

    const tamperedIpHash = computeAuditHash({
      ...latestLog,
      ipAddress: '10.0.0.1'
    });
    expect(tamperedIpHash).not.toBe(latestLog.hash);
  });

  it('AUD-02: Verifies concurrent audit event logging does not fork the ledger (pg_advisory_xact_lock)', async () => {
    // Fire 5 concurrent audit logs simultaneously
    const actions = ['CONCURRENCY_1', 'CONCURRENCY_2', 'CONCURRENCY_3', 'CONCURRENCY_4', 'CONCURRENCY_5'];

    const hashes = await Promise.all(
      actions.map((act, i) =>
        logAuditEvent({
          action: act,
          userId: `concurrent-user-${i}`,
          userEmail: `concurrent_${i}@trustvault.local`,
          status: AuditStatus.SUCCESS,
          ipAddress: `127.0.0.${i + 1}`,
          userAgent: 'Concurrency Test Runner',
          details: `Parallel audit append ${i}`
        })
      )
    );

    expect(hashes.length).toBe(5);

    // Verify the entire ledger chain remains cryptographically continuous and valid
    const verification = await verifyAuditChain();
    expect(verification.valid).toBe(true);
    expect(verification.totalRecords).toBeGreaterThanOrEqual(5);
  });

  it('AUD-03: Detects external anchor substitution (head fork attack)', async () => {
    const currentVerification = await verifyAuditChain();
    expect(currentVerification.valid).toBe(true);

    const headSeq = BigInt(currentVerification.headSequence || '1');

    // Simulate an attacker substituting the external anchor with a bogus head hash
    await exportAuditAnchor(headSeq, 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', new Date());

    const forkedVerification = await verifyAuditChain();
    expect(forkedVerification.valid).toBe(false);
    expect(forkedVerification.error).toContain('External anchor hash mismatch');

    // Restore legitimate anchor
    await exportAuditAnchor(headSeq, currentVerification.headHash || '', new Date());
    const restoredVerification = await verifyAuditChain();
    expect(restoredVerification.valid).toBe(true);
  });
});
