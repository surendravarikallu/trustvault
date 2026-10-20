import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

async function main() {
  // Find test users
  const testUsers = await prisma.user.findMany({
    where: {
      OR: [
        { email: { startsWith: 'demote_test_' } },
        { email: { startsWith: 'deact_user_' } },
        { email: { startsWith: 'mfa_prelogin_' } },
        { email: { startsWith: 'mfa_tester' } },
        { email: { startsWith: 'audit_race_' } },
        { email: { startsWith: 'prov_user_' } },
        { email: { startsWith: 'sim_user_' } }
      ]
    },
    select: { id: true, email: true }
  });

  console.log(`Found ${testUsers.length} ephemeral test users to clean up.`);

  const ids = testUsers.map(u => u.id);

  if (ids.length > 0) {
    // Delete permissions granted to or by these users
    await prisma.documentPermission.deleteMany({
      where: {
        OR: [
          { userId: { in: ids } },
          { grantedById: { in: ids } }
        ]
      }
    });

    // Delete documents owned by these users if any
    const docs = await prisma.document.findMany({
      where: { ownerId: { in: ids } },
      select: { id: true }
    });
    const docIds = docs.map(d => d.id);
    if (docIds.length > 0) {
      await prisma.documentVersion.deleteMany({ where: { documentId: { in: docIds } } });
      await prisma.documentPermission.deleteMany({ where: { documentId: { in: docIds } } });
      await prisma.document.deleteMany({ where: { id: { in: docIds } } });
    }

    // Delete the users
    const deleted = await prisma.user.deleteMany({
      where: { id: { in: ids } }
    });
    console.log(`Deleted ${deleted.count} test users.`);
  }

  // Ensure Admin, Owner, Viewer, Eve have 2FA disabled by default
  await prisma.user.updateMany({
    where: {
      email: { in: ['admin@trustvault.local', 'owner@trustvault.local', 'viewer@trustvault.local', 'eve@trustvault.local'] }
    },
    data: {
      mfaEnabled: false,
      mfaSecret: null,
      mfaBackupCodes: [],
      mfaLastTimeStep: null
    }
  });

  console.log('Ensured 2FA is false for all 4 seed accounts.');

  // Print remaining users
  const remaining = await prisma.user.findMany({
    select: { id: true, email: true, name: true, role: true, mfaEnabled: true, isActive: true },
    orderBy: [{ role: 'asc' }, { createdAt: 'desc' }]
  });

  console.log('\n--- Active System Users in Directory ---');
  for (const u of remaining) {
    console.log(`[${u.role.padEnd(6)}] ${u.name.padEnd(25)} | ${u.email.padEnd(28)} | 2FA: ${u.mfaEnabled} | Active: ${u.isActive}`);
  }
}

main().catch(console.error).finally(() => prisma.$disconnect());
