import crypto from 'crypto';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export interface LogAuditParams {
  action: 'UPLOAD' | 'DOWNLOAD' | 'VIEW' | 'EDIT' | 'DELETE' | 'GRANT_PERMISSION' | 'REVOKE_PERMISSION' | 'ACCESS_DENIED' | 'LOGIN_SUCCESS' | 'LOGIN_FAILED';
  userId?: string;
  userEmail?: string;
  documentId?: string;
  documentTitle?: string;
  status: 'SUCCESS' | 'DENIED' | 'FAILED';
  ipAddress?: string;
  userAgent?: string;
  details?: string;
}

export const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

/**
 * Computes a SHA-256 cryptographic hash over an audit entry's immutable fields and its parent's hash
 */
export function calculateAuditHash(
  sequenceNumber: number,
  timestamp: Date,
  action: string,
  userId: string | null | undefined,
  documentId: string | null | undefined,
  status: string,
  details: string | null | undefined,
  previousHash: string
): string {
  const payload = [
    sequenceNumber,
    timestamp.toISOString(),
    action,
    userId || 'ANONYMOUS',
    documentId || 'NONE',
    status,
    details || '',
    previousHash
  ].join('|');

  return crypto.createHash('sha256').update(payload).digest('hex');
}

/**
 * Records an audit log entry into the tamper-evident hash-chained ledger
 */
export async function recordAudit(params: LogAuditParams) {
  try {
    // Find previous log entry to link the hash chain
    const lastEntry = await prisma.auditLog.findFirst({
      orderBy: { sequenceNumber: 'desc' }
    });

    const sequenceNumber = lastEntry ? lastEntry.sequenceNumber + 1 : 1;
    const previousHash = lastEntry ? lastEntry.hash : GENESIS_HASH;
    const timestamp = new Date();

    const hash = calculateAuditHash(
      sequenceNumber,
      timestamp,
      params.action,
      params.userId,
      params.documentId,
      params.status,
      params.details,
      previousHash
    );

    const logEntry = await prisma.auditLog.create({
      data: {
        sequenceNumber,
        timestamp,
        action: params.action,
        userId: params.userId || null,
        userEmail: params.userEmail || null,
        documentId: params.documentId || null,
        documentTitle: params.documentTitle || null,
        status: params.status,
        ipAddress: params.ipAddress || null,
        userAgent: params.userAgent || null,
        details: params.details || null,
        previousHash,
        hash
      }
    });

    return logEntry;
  } catch (error) {
    // Crucial: audit logging failure must never fail silently in production
    console.error('[AUDIT_FATAL] Failed to record audit log:', error);
    throw error;
  }
}

/**
 * Validates the entire cryptographic hash chain of the audit trail
 * Returns valid: true if completely unaltered, or pinpoint details if tampered
 */
export async function verifyAuditChainIntegrity(): Promise<{
  valid: boolean;
  totalRecords: number;
  brokenAtSequence?: number;
  reason?: string;
  headHash?: string;
}> {
  const records = await prisma.auditLog.findMany({
    orderBy: { sequenceNumber: 'asc' }
  });

  if (records.length === 0) {
    return { valid: true, totalRecords: 0, headHash: GENESIS_HASH };
  }

  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < records.length; i++) {
    const record = records[i];

    // Check sequence continuity
    if (record.sequenceNumber !== i + 1) {
      return {
        valid: false,
        totalRecords: records.length,
        brokenAtSequence: record.sequenceNumber,
        reason: `Missing sequence gap before sequence ${record.sequenceNumber}`
      };
    }

    // Check previous hash link
    if (record.previousHash !== expectedPrevHash) {
      return {
        valid: false,
        totalRecords: records.length,
        brokenAtSequence: record.sequenceNumber,
        reason: `Broken chain link at sequence ${record.sequenceNumber}. Stored previousHash does not match prior record's hash.`
      };
    }

    // Recompute current hash
    const recomputedHash = calculateAuditHash(
      record.sequenceNumber,
      record.timestamp,
      record.action,
      record.userId,
      record.documentId,
      record.status,
      record.details,
      record.previousHash
    );

    if (record.hash !== recomputedHash) {
      return {
        valid: false,
        totalRecords: records.length,
        brokenAtSequence: record.sequenceNumber,
        reason: `Data tampering detected at sequence ${record.sequenceNumber}. Recomputed hash differs from recorded hash.`
      };
    }

    expectedPrevHash = record.hash;
  }

  return {
    valid: true,
    totalRecords: records.length,
    headHash: expectedPrevHash
  };
}
