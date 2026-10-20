import { PrismaClient } from '@prisma/client';
import { verifyAuditChain } from '../src/dal/auditDal';
import { loadAuditAnchor } from '../src/utils/auditAnchor';

const prisma = new PrismaClient();

async function main() {
  console.log('================================================================');
  console.log('AUDIT LEDGER INTEGRITY & INSPECTION REPORT');
  console.log('================================================================');

  // 1. Run cryptographic HMAC chain verification
  console.log('\n--- 1. Cryptographic HMAC-SHA256 Chain Verification ---');
  const result = await verifyAuditChain();
  console.log('Chain Status:            ', result.valid ? 'VALID (PASSED)' : 'INVALID (FAILED)');
  console.log('Total Ledger Records:    ', result.totalRecords);
  console.log('Head Sequence Height:    ', result.headSequence);
  console.log('Head HMAC-SHA256:        ', result.headHash);
  console.log('Anchor Match:            ', result.anchorMatched ? 'VERIFIED MATCH' : 'MISMATCH / MISSING');
  if (result.error) {
    console.error('Integrity Error:         ', result.error);
  }

  // 2. Inspect external anchor file
  console.log('\n--- 2. External Audit Anchor State ---');
  const anchor = loadAuditAnchor();
  if (anchor) {
    console.log('Anchor Sequence:         ', anchor.sequenceNumber);
    console.log('Anchor Hash:             ', anchor.headHash);
    console.log('Anchor Timestamp:        ', anchor.exportedAt);
  } else {
    console.log('No external anchor found on disk.');
  }

  // 3. Inspect latest 10 audit log records
  console.log('\n--- 3. Latest 10 Audit Log Records (Recent Activity) ---');
  const recentLogs = await prisma.auditLog.findMany({
    take: 10,
    orderBy: { sequenceNumber: 'desc' }
  });

  for (const log of recentLogs) {
    console.log(
      `[Seq #${log.sequenceNumber.toString().padStart(4, '0')}] ` +
      `Time: ${log.timestamp.toISOString()} | ` +
      `Action: ${log.action.padEnd(25)} | ` +
      `Status: ${log.status.padEnd(7)} | ` +
      `User: ${(log.userEmail || 'ANONYMOUS').padEnd(26)} | ` +
      `Doc: ${(log.documentTitle || log.documentId || 'N/A').slice(0, 30)}`
    );
    console.log(`   Hash:     ${log.hash}`);
    console.log(`   PrevHash: ${log.previousHash}`);
    console.log(`   Details:  ${log.details.slice(0, 80)}`);
  }

  // 4. Distribution of audit actions
  console.log('\n--- 4. Audit Log Action Distribution ---');
  const actionCounts = await prisma.auditLog.groupBy({
    by: ['action', 'status'],
    _count: { action: true },
    orderBy: { _count: { action: 'desc' } }
  });

  for (const item of actionCounts) {
    console.log(`  ${item.action.padEnd(30)} [${item.status}]: ${item._count.action} events`);
  }

  await prisma.$disconnect();
}

main().catch(async (e) => {
  console.error(e);
  await prisma.$disconnect();
  process.exit(1);
});
