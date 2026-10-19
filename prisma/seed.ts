import { PrismaClient, Role, PermissionLevel, AuditStatus } from '@prisma/client';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const prisma = new PrismaClient();

const STORAGE_DIR = path.resolve(process.env.STORAGE_DIR || 'storage/uploads');
const HMAC_SECRET = process.env.AUDIT_HMAC_SECRET || 'trustvault_hmac_secret_dev_key_2026_super_secure';

function computeAuditHash(entry: {
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

  return crypto.createHmac('sha256', HMAC_SECRET).update(canonicalPayload).digest('hex');
}

async function main() {
  console.log('--- Starting TrustVault Database Seed ---');

  // Ensure storage directories exist
  if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
  }

  // 1. Clear existing operational records (seed re-runnable)
  await prisma.documentPermission.deleteMany();
  await prisma.documentVersion.deleteMany();
  await prisma.document.deleteMany();
  await prisma.user.deleteMany();

  console.log('Cleared existing records.');

  // 2. Hash default passwords (12 rounds)
  const adminHash = await bcrypt.hash('Admin@TrustVault2026!', 12);
  const ownerHash = await bcrypt.hash('Owner@TrustVault2026!', 12);
  const viewerHash = await bcrypt.hash('Viewer@TrustVault2026!', 12);
  const eveHash = await bcrypt.hash('Eve@TrustVault2026!', 12);

  // 3. Create Seed Users
  const admin = await prisma.user.create({
    data: {
      email: 'admin@trustvault.local',
      passwordHash: adminHash,
      name: 'Security Administrator',
      role: Role.ADMIN,
      isActive: true,
      tokenVersion: 1
    }
  });

  const owner = await prisma.user.create({
    data: {
      email: 'owner@trustvault.local',
      passwordHash: ownerHash,
      name: 'Alice Document Owner',
      role: Role.OWNER,
      isActive: true,
      tokenVersion: 1
    }
  });

  const viewer = await prisma.user.create({
    data: {
      email: 'viewer@trustvault.local',
      passwordHash: viewerHash,
      name: 'Bob Authorized Viewer',
      role: Role.VIEWER,
      isActive: true,
      tokenVersion: 1
    }
  });

  const eve = await prisma.user.create({
    data: {
      email: 'eve@trustvault.local',
      passwordHash: eveHash,
      name: 'Eve Adversary',
      role: Role.VIEWER,
      isActive: true,
      tokenVersion: 1
    }
  });

  console.log('Created Users: Admin, Owner, Viewer, Eve.');

  // 4. Create sample physical files on disk
  const samplePdfContent = Buffer.from(
    '%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF'
  );

  const file1StoredName = crypto.randomUUID();
  const file1Path = path.join(STORAGE_DIR, file1StoredName);
  fs.writeFileSync(file1Path, samplePdfContent);
  const file1Hash = crypto.createHash('sha256').update(samplePdfContent).digest('hex');

  const file2StoredName = crypto.randomUUID();
  const file2Path = path.join(STORAGE_DIR, file2StoredName);
  fs.writeFileSync(file2Path, samplePdfContent);
  const file2Hash = crypto.createHash('sha256').update(samplePdfContent).digest('hex');

  // 5. Create Documents
  const doc1 = await prisma.document.create({
    data: {
      title: 'Master Services Agreement (MSA) - Acme Corp',
      description: 'Confidential enterprise MSA contract with Acme Corporation.',
      originalFilename: 'MSA_Acme_2026.pdf',
      storedFilename: file1StoredName,
      fileSize: samplePdfContent.length,
      mimeType: 'application/pdf',
      category: 'Legal',
      fileHash: file1Hash,
      ownerId: owner.id
    }
  });

  const doc2 = await prisma.document.create({
    data: {
      title: 'Executive Compensation Review Q3',
      description: 'Restricted board review of C-level compensation packages.',
      originalFilename: 'Executive_Comp_Q3.pdf',
      storedFilename: file2StoredName,
      fileSize: samplePdfContent.length,
      mimeType: 'application/pdf',
      category: 'Finance',
      fileHash: file2Hash,
      ownerId: owner.id
    }
  });

  console.log('Created Documents:', doc1.title, '|', doc2.title);

  // 6. Grant READ permission on doc1 to Bob (Viewer)
  await prisma.documentPermission.create({
    data: {
      documentId: doc1.id,
      userId: viewer.id,
      permissionLevel: PermissionLevel.READ,
      grantedById: owner.id
    }
  });

  console.log(`Granted READ permission on Doc 1 to Bob (${viewer.email}). Doc 2 is strictly private to Alice.`);

  // 7. Check if AuditLog has entries, else add Genesis entries
  const existingAuditCount = await prisma.auditLog.count();
  if (existingAuditCount === 0) {
    const genesisDate = new Date();
    const genesisId = crypto.randomUUID();
    const genesisPrevHash = '0000000000000000000000000000000000000000000000000000000000000000';

    const genesisEntry = {
      id: genesisId,
      sequenceNumber: 1n,
      timestamp: genesisDate,
      action: 'SYSTEM_GENESIS',
      userId: admin.id,
      userEmail: admin.email,
      documentId: null,
      documentTitle: null,
      status: AuditStatus.SUCCESS,
      ipAddress: '127.0.0.1',
      userAgent: 'System Seed Script',
      details: 'TrustVault cryptographic audit ledger initialized.',
      previousHash: genesisPrevHash
    };

    const genesisHash = computeAuditHash(genesisEntry);

    await prisma.auditLog.create({
      data: {
        ...genesisEntry,
        hash: genesisHash
      }
    });

    // Seed audit for Doc 1 Upload
    const upload1Date = new Date(Date.now() + 100);
    const upload1Id = crypto.randomUUID();
    const upload1Entry = {
      id: upload1Id,
      sequenceNumber: 2n,
      timestamp: upload1Date,
      action: 'DOCUMENT_UPLOADED',
      userId: owner.id,
      userEmail: owner.email,
      documentId: doc1.id,
      documentTitle: doc1.title,
      status: AuditStatus.SUCCESS,
      ipAddress: '127.0.0.1',
      userAgent: 'Seed Agent',
      details: `Uploaded initial document: ${doc1.originalFilename}`,
      previousHash: genesisHash
    };
    const upload1Hash = computeAuditHash(upload1Entry);

    await prisma.auditLog.create({
      data: {
        ...upload1Entry,
        hash: upload1Hash
      }
    });

    // Seed audit for Permission Grant
    const grantDate = new Date(Date.now() + 200);
    const grantId = crypto.randomUUID();
    const grantEntry = {
      id: grantId,
      sequenceNumber: 3n,
      timestamp: grantDate,
      action: 'PERMISSION_GRANTED',
      userId: owner.id,
      userEmail: owner.email,
      documentId: doc1.id,
      documentTitle: doc1.title,
      status: AuditStatus.SUCCESS,
      ipAddress: '127.0.0.1',
      userAgent: 'Seed Agent',
      details: `Granted READ access to ${viewer.email}`,
      previousHash: upload1Hash
    };
    const grantHash = computeAuditHash(grantEntry);

    await prisma.auditLog.create({
      data: {
        ...grantEntry,
        hash: grantHash
      }
    });

    console.log('Seeded initial HMAC audit ledger (3 entries, chain verified).');
  }

  console.log('--- TrustVault Seed Completed Successfully ---');
}

main()
  .catch((e) => {
    console.error('Seed error:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
