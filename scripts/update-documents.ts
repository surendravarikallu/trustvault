import { PrismaClient, PermissionLevel } from '@prisma/client';
import fs from 'fs';
import path from 'path';
import { StorageService } from '../src/services/storageService';
import { ENTERPRISE_DOCUMENTS } from '../src/utils/generateEnterprisePdfs';
import { config } from '../src/config';

const prisma = new PrismaClient();

async function main() {
  console.log('=== Updating TrustVault Documents With Real Enterprise Context ===');

  const owner = await prisma.user.findUnique({
    where: { email: 'owner@trustvault.local' },
  });

  const viewer = await prisma.user.findUnique({
    where: { email: 'viewer@trustvault.local' },
  });

  if (!owner) {
    throw new Error('Alice (owner@trustvault.local) was not found in the database. Run seed first.');
  }

  if (!fs.existsSync(config.tempDir)) {
    fs.mkdirSync(config.tempDir, { recursive: true });
  }

  // 1. Soft-delete lingering test dummy documents
  const cleanedDummies = await prisma.document.updateMany({
    where: {
      title: 'Version Retention Document',
      isDeleted: false,
    },
    data: {
      isDeleted: true,
      deletedAt: new Date(),
    },
  });
  console.log(`Cleaned up ${cleanedDummies.count} lingering test dummy documents.`);

  // 2. Generate and persist each rich enterprise PDF
  for (const docTemplate of ENTERPRISE_DOCUMENTS) {
    console.log(`Generating authentic multi-page PDF: ${docTemplate.filename}...`);
    const pdfBuffer = await docTemplate.build();

    const tempFilePath = path.join(config.tempDir, `temp_${Date.now()}_${docTemplate.filename}`);
    await fs.promises.writeFile(tempFilePath, pdfBuffer);

    const { storedFilename, fileHash, fileSize } = await StorageService.persistFile(tempFilePath);
    await fs.promises.unlink(tempFilePath);

    console.log(`  -> Encrypted & stored as ${storedFilename} (${fileSize} bytes)`);

    const existingDoc = await prisma.document.findFirst({
      where: {
        originalFilename: docTemplate.filename,
        isDeleted: false,
      },
    });

    let documentId: string;

    if (existingDoc) {
      if (existingDoc.storedFilename !== storedFilename) {
        await StorageService.deleteFile(existingDoc.storedFilename);
      }

      const updated = await prisma.document.update({
        where: { id: existingDoc.id },
        data: {
          title: docTemplate.title,
          description: docTemplate.description,
          storedFilename,
          fileSize,
          fileHash,
          mimeType: 'application/pdf',
          category: docTemplate.category,
          isDeleted: false,
          deletedAt: null,
          ownerId: owner.id,
        },
      });
      documentId = updated.id;
      console.log(`  -> Updated existing document record: "${updated.title}" [${documentId}]`);
    } else {
      const created = await prisma.document.create({
        data: {
          title: docTemplate.title,
          description: docTemplate.description,
          originalFilename: docTemplate.filename,
          storedFilename,
          fileSize,
          fileHash,
          mimeType: 'application/pdf',
          category: docTemplate.category,
          ownerId: owner.id,
        },
      });
      documentId = created.id;
      console.log(`  -> Created new document record: "${created.title}" [${documentId}]`);
    }

    if (viewer) {
      if (docTemplate.filename === 'Executive_Comp_Q3.pdf') {
        await prisma.documentPermission.deleteMany({
          where: {
            documentId,
            userId: viewer.id,
          },
        });
        console.log(`  -> Ensured "${docTemplate.title}" is strictly restricted to Owner.`);
      } else {
        const permLevel = docTemplate.filename === 'Incident_Response_Plan_2026.pdf'
          ? PermissionLevel.EDIT
          : PermissionLevel.READ;

        await prisma.documentPermission.upsert({
          where: {
            documentId_userId: {
              documentId,
              userId: viewer.id,
            },
          },
          update: {
            permissionLevel: permLevel,
            expiresAt: null,
            burnOnDownload: false,
            previewOnly: false,
          },
          create: {
            documentId,
            userId: viewer.id,
            permissionLevel: permLevel,
            grantedById: owner.id,
          },
        });
        console.log(`  -> Granted ${permLevel} permission to Bob (${viewer.email}).`);
      }
    }
  }

  // 3. Seed architectural Markdown document
  const mdFilename = 'TrustVault_Security_Architecture.md';
  const mdTitle = 'TrustVault Cryptographic Security Model & Architecture Matrix';
  const mdDescription = 'Comprehensive architectural matrix detailing defensive invariants against all OWASP, CWE, and timing-attack vectors.';
  const mdContent = [
    '# TrustVault Cryptographic Security Model & Invariants Matrix',
    '',
    '**Document Classification:** RESTRICTED // ENGINEERING GOVERNANCE',
    '**Security Standard:** NIST SP 800-207 Zero-Trust Architecture',
    '**Publication Date:** October 20, 2026',
    '**Lead Architect:** Alice Vance, VP of Security & Infrastructure',
    '',
    '---',
    '',
    '## 1. Architectural Invariants',
    '',
    '| Security Dimension | Defense Primitives | Standard / Spec |',
    '| :--- | :--- | :--- |',
    '| **Storage at Rest** | AES-256-GCM Envelope Encryption (TV_AES256_GCM_v1:) | FIPS 197 / NIST SP 800-38D |',
    '| **Audit Immutability** | Append-Only HMAC-SHA256 Chaining (13 Canonical Columns) | RFC 2104 / ISO 27001 CC7.2 |',
    '| **Concurrency Lock** | PostgreSQL Transaction-Level Advisory Lock (ID: 749281) | Monotonic Sequence Monotonicity |',
    '| **Access Gatekeeper** | Single-Gatekeeper DAL with Mandatory HTTP 404 on IDOR probes | CWE-639 / CWE-209 Mitigation |',
    '| **Authentication** | RFC 6238 TOTP with Single-Step Replay Attack Prevention | RFC 6238 / OWASP ASVS 2.1 |',
    '| **Session Control** | Monotonic Token Version Invalidation upon Role Mutation | Immediate Session Termination |',
    '| **Disk Sanitization** | NIST SP 800-88 3-Pass Entropy Overwriting (Crypto-Shred) | NIST SP 800-88 Rev. 1 |',
    '',
    '---',
    '',
    '## 2. Envelope Encryption Binary Specification',
    '',
    'Storage blobs are never written in plaintext to physical storage media. Files are wrapped in a 45-byte authenticated envelope:',
    '',
    '```',
    '+-----------------------+---------------------+--------------------+-----------------------+',
    '| Magic Header (17B)    | Unique IV (12B)     | Auth Tag (16B)     | Ciphertext (N Bytes)  |',
    '| "TV_AES256_GCM_v1:"   | CSPRNG randomBytes  | AES-GCM 128-bit    | AES-256-GCM Payload   |',
    '+-----------------------+---------------------+--------------------+-----------------------+',
    '```',
    '',
    '---',
    '',
    '## 3. Threat Model & Verification Guarantees',
    '',
    '1. **Physical Volume Theft (L-17):** Raw disk blocks contain high-entropy ciphertext with no unencrypted metadata.',
    '2. **Audit Ledger Truncation (L-13):** External state anchor detects deletion of historical audit entries immediately.',
    '3. **Existence Enumeration Oracle (L-06):** Probes on unauthorized documents return HTTP 404, matching non-existent resources.',
    '4. **Single-Use Transfer Protocol (BOD):** Ephemeral links self-destruct upon single binary download.',
    '5. **In-Browser Ephemeral Preview:** Restricted preview tokens allow in-memory PDF.js canvas rendering while returning HTTP 403 on binary exfiltration.',
    '',
    '*Approved by TrustVault Security Architecture Board.*'
  ].join('\n');

  const mdBuffer = Buffer.from(mdContent, 'utf-8');
  const tempMdPath = path.join(config.tempDir, `temp_${Date.now()}_${mdFilename}`);
  await fs.promises.writeFile(tempMdPath, mdBuffer);
  const { storedFilename: mdStored, fileHash: mdHash, fileSize: mdSize } = await StorageService.persistFile(tempMdPath);
  await fs.promises.unlink(tempMdPath);

  const existingMd = await prisma.document.findFirst({
    where: { originalFilename: mdFilename, isDeleted: false },
  });

  let mdDocId: string;
  if (existingMd) {
    const updated = await prisma.document.update({
      where: { id: existingMd.id },
      data: {
        title: mdTitle,
        description: mdDescription,
        storedFilename: mdStored,
        fileSize: mdSize,
        fileHash: mdHash,
        mimeType: 'text/markdown',
        category: 'Architecture',
        ownerId: owner.id,
      },
    });
    mdDocId = updated.id;
  } else {
    const created = await prisma.document.create({
      data: {
        title: mdTitle,
        description: mdDescription,
        originalFilename: mdFilename,
        storedFilename: mdStored,
        fileSize: mdSize,
        fileHash: mdHash,
        mimeType: 'text/markdown',
        category: 'Architecture',
        ownerId: owner.id,
      },
    });
    mdDocId = created.id;
  }

  if (viewer) {
    await prisma.documentPermission.upsert({
      where: {
        documentId_userId: {
          documentId: mdDocId,
          userId: viewer.id,
        },
      },
      update: {
        permissionLevel: PermissionLevel.READ,
      },
      create: {
        documentId: mdDocId,
        userId: viewer.id,
        permissionLevel: PermissionLevel.READ,
        grantedById: owner.id,
      },
    });
    console.log(`  -> Granted READ permission on "${mdTitle}" to Bob.`);
  }

  console.log('\n=== Real Context Document Update Completed Successfully ===');
}

main()
  .catch((err) => {
    console.error('Update failed:', err);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
