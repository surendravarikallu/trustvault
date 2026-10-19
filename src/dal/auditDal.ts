import { PrismaClient, AuditStatus } from '@prisma/client';
import crypto from 'crypto';
import { config } from '../config';
import { exportAuditAnchor, loadAuditAnchor } from '../utils/auditAnchor';

const prisma = new PrismaClient();

export const AUDIT_LOCK_ID = 749281;
export const GENESIS_PREV_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export interface AuditLogInput {
  action: string;
  userId?: string | null;
  userEmail?: string | null;
  documentId?: string | null;
  documentTitle?: string | null;
  status: AuditStatus;
  ipAddress: string;
  userAgent: string;
  details: string;
}

export interface AuditVerificationResult {
  valid: boolean;
  totalRecords: number;
  headSequence?: string;
  headHash?: string;
  anchorMatched?: boolean;
  error?: string;
  compromisedSequence?: string;
}

/**
 * Computes deterministic HMAC-SHA256 covering all 13 canonical columns.
 * Defense against Loophole L-12: Audit Tampering.
 */
export function computeAuditHash(entry: {
  id: string;
  sequenceNumber: bigint;
  timestamp: Date;
  action: string;
  userId: string | null;
  userEmail: string | null;
  documentId: string | null;
  documentTitle: string | null;
  status: string;
  ipAddress: string;
  userAgent: string;
  details: string;
  previousHash: string;
}): string {
  const canonicalPayload = JSON.stringify({
    action: entry.action,
    details: entry.details,
    documentId: entry.documentId ?? null,
    documentTitle: entry.documentTitle ?? null,
    id: entry.id,
    ipAddress: entry.ipAddress,
    previousHash: entry.previousHash,
    sequenceNumber: entry.sequenceNumber.toString(),
    status: entry.status,
    timestamp: entry.timestamp.toISOString(),
    userAgent: entry.userAgent,
    userEmail: entry.userEmail ?? null,
    userId: entry.userId ?? null
  });

  return crypto.createHmac('sha256', config.auditHmacSecret).update(canonicalPayload).digest('hex');
}

/**
 * Appends an audit event inside a serialized advisory lock.
 * Defense against Loophole L-10 (Sequence gaps) and L-14 (Concurrency forks).
 */
export async function logAuditEvent(input: AuditLogInput, customTx?: any): Promise<string> {
  const executeLog = async (tx: any) => {
    // 1. Acquire PostgreSQL advisory transaction lock
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(${AUDIT_LOCK_ID})`;

    // 2. Fetch the true current head
    const lastEntry = await tx.auditLog.findFirst({
      orderBy: { sequenceNumber: 'desc' },
      select: { sequenceNumber: true, hash: true }
    });

    const sequenceNumber = (lastEntry?.sequenceNumber ?? 0n) + 1n;
    const previousHash = lastEntry?.hash ?? GENESIS_PREV_HASH;
    const id = crypto.randomUUID();
    const timestamp = new Date();

    const entryToHash = {
      id,
      sequenceNumber,
      timestamp,
      action: input.action,
      userId: input.userId ?? null,
      userEmail: input.userEmail ?? null,
      documentId: input.documentId ?? null,
      documentTitle: input.documentTitle ?? null,
      status: input.status,
      ipAddress: input.ipAddress || '127.0.0.1',
      userAgent: input.userAgent || 'Unknown',
      details: input.details,
      previousHash
    };

    const hash = computeAuditHash(entryToHash);

    await tx.auditLog.create({
      data: {
        ...entryToHash,
        hash
      }
    });

    // Periodically export anchor (every 25 events or first event)
    if (sequenceNumber % 25n === 0n || sequenceNumber === 1n) {
      await exportAuditAnchor(sequenceNumber, hash, timestamp);
    }

    return hash;
  };

  if (customTx) {
    return executeLog(customTx);
  } else {
    return prisma.$transaction(async (tx) => executeLog(tx), {
      timeout: 10000
    });
  }
}

/**
 * Logs an ACCESS_DENIED attempt inside an autonomous database transaction.
 */
export async function logAccessDenied(
  user: { id: string; email: string } | null,
  documentId: string,
  action: string,
  reqContext: { ip: string; userAgent: string; details?: string }
): Promise<string> {
  return logAuditEvent({
    action: 'ACCESS_DENIED',
    userId: user?.id ?? null,
    userEmail: user?.email ?? null,
    documentId,
    documentTitle: null,
    status: AuditStatus.DENIED,
    ipAddress: reqContext.ip,
    userAgent: reqContext.userAgent,
    details: reqContext.details || `Access denied for action '${action}' on document ${documentId}`
  });
}

/**
 * Validates the full HMAC chain and asserts match with external anchor.
 * Defense against Loophole L-13: Audit Tail Truncation.
 */
export async function verifyAuditChain(): Promise<AuditVerificationResult> {
  const records = await prisma.auditLog.findMany({
    orderBy: { sequenceNumber: 'asc' }
  });

  if (records.length === 0) {
    return { valid: true, totalRecords: 0 };
  }

  let expectedPreviousHash = GENESIS_PREV_HASH;
  let expectedSequence = 1n;

  for (const entry of records) {
    if (entry.sequenceNumber !== expectedSequence) {
      return {
        valid: false,
        totalRecords: records.length,
        error: `Sequence discontinuity detected at sequence ${entry.sequenceNumber}. Expected ${expectedSequence}.`,
        compromisedSequence: entry.sequenceNumber.toString()
      };
    }

    if (entry.previousHash !== expectedPreviousHash) {
      return {
        valid: false,
        totalRecords: records.length,
        error: `Previous hash mismatch at sequence ${entry.sequenceNumber}. Chain is broken.`,
        compromisedSequence: entry.sequenceNumber.toString()
      };
    }

    const recalculatedHash = computeAuditHash({
      id: entry.id,
      sequenceNumber: entry.sequenceNumber,
      timestamp: entry.timestamp,
      action: entry.action,
      userId: entry.userId,
      userEmail: entry.userEmail,
      documentId: entry.documentId,
      documentTitle: entry.documentTitle,
      status: entry.status,
      ipAddress: entry.ipAddress,
      userAgent: entry.userAgent,
      details: entry.details,
      previousHash: entry.previousHash
    });

    if (entry.hash !== recalculatedHash) {
      return {
        valid: false,
        totalRecords: records.length,
        error: `Cryptographic HMAC mismatch at sequence ${entry.sequenceNumber}. Entry content has been tampered with.`,
        compromisedSequence: entry.sequenceNumber.toString()
      };
    }

    expectedPreviousHash = entry.hash;
    expectedSequence = expectedSequence + 1n;
  }

  const headEntry = records[records.length - 1];

  const anchor = loadAuditAnchor();
  let anchorMatched = true;

  if (anchor) {
    const anchorSeq = BigInt(anchor.sequenceNumber);
    if (headEntry.sequenceNumber < anchorSeq) {
      return {
        valid: false,
        totalRecords: records.length,
        headSequence: headEntry.sequenceNumber.toString(),
        headHash: headEntry.hash,
        anchorMatched: false,
        error: `Audit tail truncation detected! External anchor references sequence ${anchor.sequenceNumber}, but database head is only ${headEntry.sequenceNumber}. Recent rows were deleted!`
      };
    }

    const anchorRecord = records.find((r) => r.sequenceNumber === anchorSeq);
    if (!anchorRecord || anchorRecord.hash !== anchor.headHash) {
      return {
        valid: false,
        totalRecords: records.length,
        anchorMatched: false,
        error: `External anchor hash mismatch at sequence ${anchor.sequenceNumber}. Ledger head was forked or substituted!`
      };
    }
  }

  return {
    valid: true,
    totalRecords: records.length,
    headSequence: headEntry.sequenceNumber.toString(),
    headHash: headEntry.hash,
    anchorMatched
  };
}

/**
 * Retrieves paginated audit logs for administrative views
 */
export async function getAuditLogs(filter?: { action?: string; documentId?: string; userId?: string }, page = 1, limit = 50) {
  const where: any = {};
  if (filter?.action) {
    where.action = filter.action;
  }
  if (filter?.documentId) {
    where.documentId = filter.documentId;
  }
  if (filter?.userId) {
    where.userId = filter.userId;
  }

  const skip = (page - 1) * limit;
  const [total, logs] = await Promise.all([
    prisma.auditLog.count({ where }),
    prisma.auditLog.findMany({
      where,
      skip,
      take: limit,
      orderBy: { sequenceNumber: 'desc' }
    })
  ]);

  const serializedLogs = logs.map((log) => ({
    ...log,
    sequenceNumber: log.sequenceNumber.toString()
  }));

  return { total, page, limit, logs: serializedLogs };
}
