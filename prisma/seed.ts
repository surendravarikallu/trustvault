import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { calculateAuditHash, GENESIS_HASH } from '../src/services/auditService.js';
import { config } from '../src/config.js';

const prisma = new PrismaClient();

async function main() {
  console.log('[SEED] Starting TrustVault database seeding...');

  // Ensure storage dir exists
  if (!fs.existsSync(config.uploadDir)) {
    fs.mkdirSync(config.uploadDir, { recursive: true });
  }

  // 1. Clean existing tables
  await prisma.documentPermission.deleteMany({});
  await prisma.auditLog.deleteMany({});
  await prisma.document.deleteMany({});
  await prisma.user.deleteMany({});

  // 2. Hash passwords
  const adminPass = await bcrypt.hash('AdminPassword123!', 12);
  const ownerPass = await bcrypt.hash('OwnerPassword123!', 12);
  const viewerPass = await bcrypt.hash('ViewerPassword123!', 12);
  const evePass = await bcrypt.hash('EvePassword123!', 12);

  // 3. Create Users
  const admin = await prisma.user.create({
    data: {
      email: 'admin@trustvault.com',
      passwordHash: adminPass,
      name: 'System Administrator',
      role: 'ADMIN'
    }
  });

  const alice = await prisma.user.create({
    data: {
      email: 'alice.owner@trustvault.com',
      passwordHash: ownerPass,
      name: 'Alice Jenkins (Legal Lead)',
      role: 'OWNER'
    }
  });

  const bob = await prisma.user.create({
    data: {
      email: 'bob.viewer@trustvault.com',
      passwordHash: viewerPass,
      name: 'Bob Martinez (Compliance Reviewer)',
      role: 'VIEWER'
    }
  });

  const eve = await prisma.user.create({
    data: {
      email: 'eve.intruder@trustvault.com',
      passwordHash: evePass,
      name: 'Eve Adams (External Auditor)',
      role: 'VIEWER'
    }
  });

  console.log('[SEED] Created 4 users (Admin, Alice Owner, Bob Viewer, Eve Intruder)');

  // 4. Create sample document binaries on disk
  const samplePdfContent = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n2 0 obj\n<<\n/Type /Pages\n/Kids [3 0 R]\n/Count 1\n>>\nendobj\n3 0 obj\n<<\n/Type /Page\n/Parent 2 0 R\n/MediaBox [0 0 612 792]\n/Contents 4 0 R\n>>\nendobj\n4 0 obj\n<<\n/Length 44\n>>\nstream\nBT\n/F1 24 Tf\n100 700 Td\n(TrustVault Confidential Document) Tj\nET\nendstream\nendobj\nxref\n0 5\n0000000000 65535 f \n0000000018 00000 n \n0000000077 00000 n \n0000000133 00000 n \n0000000222 00000 n \ntrailer\n<<\n/Root 1 0 R\n/Size 5\n>>\nstartxref\n316\n%%EOF\n'
  );

  const doc1Stored = crypto.randomUUID();
  fs.writeFileSync(path.join(config.uploadDir, doc1Stored), samplePdfContent);

  const doc2Stored = crypto.randomUUID();
  fs.writeFileSync(path.join(config.uploadDir, doc2Stored), samplePdfContent);

  const doc3Stored = crypto.randomUUID();
  fs.writeFileSync(path.join(config.uploadDir, doc3Stored), samplePdfContent);

  const fileHash = crypto.createHash('sha256').update(samplePdfContent).digest('hex');

  // 5. Create Documents
  const doc1 = await prisma.document.create({
    data: {
      title: 'Master Service Agreement 2026 - Acme Corp',
      description: 'Confidential corporate vendor contract and pricing schedule.',
      originalFilename: 'Acme_MSA_2026.pdf',
      storedFilename: doc1Stored,
      fileSize: samplePdfContent.length,
      mimeType: 'application/pdf',
      category: 'Contracts',
      fileHash,
      ownerId: alice.id
    }
  });

  const doc2 = await prisma.document.create({
    data: {
      title: 'Executive Compensation & Bonus Review Q3',
      description: 'Highly confidential board-level compensation data.',
      originalFilename: 'Executive_Comp_Q3.pdf',
      storedFilename: doc2Stored,
      fileSize: samplePdfContent.length,
      mimeType: 'application/pdf',
      category: 'Financial',
      fileHash,
      ownerId: alice.id
    }
  });

  const doc3 = await prisma.document.create({
    data: {
      title: 'TrustVault System Security & Penetration Report',
      description: 'Annual third-party security verification report.',
      originalFilename: 'TrustVault_PenTest_2026.pdf',
      storedFilename: doc3Stored,
      fileSize: samplePdfContent.length,
      mimeType: 'application/pdf',
      category: 'Audit',
      fileHash,
      ownerId: admin.id
    }
  });

  console.log('[SEED] Created 3 sample documents');

  // 6. Grant Bob READ permission on Document 1 (Doc 2 is strictly private to Alice!)
  await prisma.documentPermission.create({
    data: {
      documentId: doc1.id,
      userId: bob.id,
      permissionLevel: 'READ',
      grantedById: alice.id
    }
  });

  console.log('[SEED] Granted Bob READ access on Document 1. Document 2 remains restricted.');

  // 7. Initialize Genesis cryptographic audit trail
  const seedEvents = [
    { action: 'LOGIN_SUCCESS', userId: admin.id, email: admin.email, details: 'Admin initial setup' },
    { action: 'UPLOAD', userId: alice.id, email: alice.email, docId: doc1.id, docTitle: doc1.title, details: `Uploaded ${doc1.originalFilename}` },
    { action: 'GRANT_PERMISSION', userId: alice.id, email: alice.email, docId: doc1.id, docTitle: doc1.title, details: `Granted READ to ${bob.email}` },
    { action: 'UPLOAD', userId: alice.id, email: alice.email, docId: doc2.id, docTitle: doc2.title, details: `Uploaded ${doc2.originalFilename}` }
  ];

  let prevHash = GENESIS_HASH;
  for (let i = 0; i < seedEvents.length; i++) {
    const e = seedEvents[i];
    const seq = i + 1;
    const now = new Date(Date.now() - (seedEvents.length - i) * 60000);
    const hash = calculateAuditHash(seq, now, e.action, e.userId, e.docId, 'SUCCESS', e.details, prevHash);

    await prisma.auditLog.create({
      data: {
        sequenceNumber: seq,
        timestamp: now,
        action: e.action,
        userId: e.userId,
        userEmail: e.email,
        documentId: e.docId || null,
        documentTitle: e.docTitle || null,
        status: 'SUCCESS',
        ipAddress: '127.0.0.1',
        userAgent: 'TrustVault Seeder Engine',
        details: e.details,
        previousHash: prevHash,
        hash
      }
    });

    prevHash = hash;
  }

  console.log('[SEED] Seeded tamper-evident audit ledger with cryptographic verification.');
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
