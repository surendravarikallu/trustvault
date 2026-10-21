import { prisma } from '../prisma';

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

/**
 * Asserts that the active database connection does not possess superuser,
 * createdb, or createrole privileges. Refuses server boot if true.
 */
export async function assertNonPrivilegedRuntimeRole(): Promise<void> {
  const result: any = await prisma.$queryRawUnsafe(
    'SELECT current_user AS role_name, (rolsuper OR rolcreatedb OR rolcreaterole) AS is_privileged FROM pg_roles WHERE rolname = current_user'
  );
  if (result?.[0]?.is_privileged) {
    throw new Error(
      `CRITICAL SECURITY VIOLATION: Refusing to start server. The application database connection is running as privileged role '${result[0].role_name}' (rolsuper, rolcreatedb, or rolcreaterole is true). Production runtime must connect via the least-privileged 'trustvault_app' role.`
    );
  }
}

