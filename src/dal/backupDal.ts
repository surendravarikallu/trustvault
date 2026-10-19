import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function exportDatabaseSnapshot() {
  const [users, documents, versions, permissions, auditLogs] = await Promise.all([
    prisma.user.findMany(),
    prisma.document.findMany(),
    prisma.documentVersion.findMany(),
    prisma.documentPermission.findMany(),
    prisma.auditLog.findMany({ orderBy: { sequenceNumber: 'asc' } })
  ]);

  const serializedAuditLogs = auditLogs.map((log) => ({
    ...log,
    sequenceNumber: log.sequenceNumber.toString()
  }));

  return {
    users,
    documents,
    versions,
    permissions,
    auditLogs: serializedAuditLogs
  };
}

export async function pingDatabaseHealth(): Promise<{ ok: boolean; latencyMs: number }> {
  const start = Date.now();
  await prisma.$queryRaw`SELECT 1`;
  const latencyMs = Date.now() - start;
  return { ok: true, latencyMs };
}
