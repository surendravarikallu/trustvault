# TrustVault — Architecture Context & Engineering Handover (CONTEXT_HANDOVER.md)

> **Purpose of this Document:**  
> This file contains the complete, unabridged technical context, design decisions, architectural invariants, database schemas, threat models, and next implementation steps for **TrustVault**. If you clone or pull this repository onto another laptop or environment, reading this single document gives you 100% of the context needed to continue building without missing a beat.

---

## 1. Project Overview & Core Philosophy

**TrustVault** is a hardened, zero-trust document vault designed for security-first enterprise document management. It is being built to withstand hostile judge evaluation, penetration testing, and mutation testing.

### The Guiding Engineering Principles
1. **Structural Impossibility over Redundant Conventions:**  
   We reject the false claim of "defense-in-depth through duplicate checks". If a controller has a redundant check behind a middleware, removing the middleware leaves tests passing, which proves the test suite was ineffective. Instead, all data access flows through a single Data Access Layer (`src/dal/documentDal.ts`). Controllers cannot query raw files or obtain disk filenames without passing through `loadDocumentFor()`.
2. **Deny-by-Default:**  
   Zero implicit grants, zero folder inheritance, zero wildcard permissions, zero unauthenticated endpoints for documents.
3. **Separation of Detection vs. Prevention:**  
   Storage opacity (UUIDs) is obscurity; audit logging is detection. Neither is an authorization layer. The authorization layer is strictly the Data Access Layer.
4. **Passing Mutation Testing:**  
   If a judge deletes or comments out the authorization check in `loadDocumentFor()`, the corresponding security route test **must fail immediately (go RED)**.

---

## 2. Locked Technical Stack

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Backend Runtime** | Node.js (v20+ LTS) | Mature asynchronous I/O and stream handling |
| **Language** | TypeScript (strict mode) | Compile-time safety and type validation |
| **HTTP Framework**| Express.js | Granular middleware pipeline and fine-grained socket control |
| **Database** | PostgreSQL | Dual database roles, transactional advisory locks (`pg_advisory_xact_lock`), audit mutation triggers |
| **ORM & Querying**| Prisma ORM + Zod | Parameterized queries; strict schema validation on all inputs |
| **Frontend** | React (Vite + TypeScript) | Lightweight, fast SPA with in-memory Blob handling |
| **Hosting & Network**| Local 24/7 host + Cloudflare Tunnel | HTTPS termination, zero open inbound router ports, IP extraction via `CF-Connecting-IP` |
| **Authentication** | JWT (identity only) + `tokenVersion` | Short-lived (8h), zero permission claims, instant demotion/revocation |
| **Password Hashing**| bcrypt (12 rounds) | CPU-hard hashing with dummy compare to neutralize timing attacks |

---

## 3. Core Architectural Invariants (Must NEVER Be Broken)

1. **Enforced DAL Boundary via ESLint:**
   * All document queries reside exclusively in `src/dal/documentDal.ts`.
   * ESLint rule `no-restricted-imports` bans `@prisma/client` from `src/controllers/` and `src/routes/`.
   * A shared `visibleDocumentsWhere(user)` Prisma predicate is used by both `loadDocumentFor`, `listDocuments`, and `searchDocuments` to eliminate authorization drift.
2. **The Gatekeeper: `loadDocumentFor(user, id, action, reqContext)`:**
   * Takes user context, document UUID, requested action (`read`, `download`, `edit`, `delete`, `manage_permissions`), and request context (IP, User Agent).
   * If access is denied, it writes the `ACCESS_DENIED` audit row inside an **independent database transaction** (so it commits even though the request fails) and throws a typed error.
   * Returns document metadata and the disk path (`storedFilename`) **only upon authorization**.
3. **Three Roles Hierarchy:**
   * `VIEWER`: Default role on registration. Can read/download explicitly granted documents. **Cannot upload files.**
   * `OWNER`: Promoted by Admin via `PATCH /api/admin/users/:id/role`. Can upload documents, grant/revoke permissions on owned documents, and upload new versions.
   * `ADMIN`: System operator. Can view metadata, audit logs, verify integrity, deactivate users, and change roles. **Admins CANNOT download or view document contents without an explicit grant from the owner.**
4. **Owner-Only Permission Authority:**
   * Editors **cannot** re-share or grant permissions. Only the document owner can grant or revoke.
   * Admins have no "self-grant" backdoors.
5. **Status Code Contract (404 vs 403):**
   * **404 Not Found**: Returned when the user has **no visibility** (neither owner nor grantee) to prevent document existence enumeration.
   * **403 Forbidden**: Returned when the user has visibility (e.g. `READ` grantee) but attempts an unauthorized action (e.g. `PUT /documents/:id`).
6. **Audit Ledger Guarantees:**
   * **No Foreign Key on `documentId`**: Stored as an unconstrained plain string/UUID snapshot alongside `documentTitle`. Non-existent UUID probes log safely without 500 errors, and document deletions never mutate past audit rows via `SET NULL`.
   * **HMAC-SHA256 with External Secret**: All 13 columns are hashed using `AUDIT_HMAC_SECRET` stored outside the database.
   * **Canonical JSON**: Key-sorted, compact JSON serialization. `sequenceNumber` is converted to string to prevent `BigInt` serialization crashes.
   * **Explicit Millisecond Timestamps**: Generated in Node.js ISO format prior to insertion to prevent Postgres microsecond drift.
   * **Advisory Lock Concurrency**: Serialized with `SELECT pg_advisory_xact_lock(749281)` to eliminate chain forks.
   * **External Anchor (`storage/audit_anchor.json`)**: Periodically exported to detect tail truncation.
   * **Fail-Closed on Downloads**: If the audit write fails during download, the request fails with 500 and no file bytes are streamed.
7. **Session Invalidation & Revocation:**
   * `tokenVersion` on `User` table. On role change, deactivation, or logout, `tokenVersion` increments, immediately invalidating active JWTs.
8. **Upload & Storage Hardening:**
   * Files stored outside web root with UUID filenames and no extensions.
   * Multi-stage upload pipeline: extension whitelist, buffer magic bytes inspection (`file-type`), null-byte checks, 15MB cap, and temp-file unlinking in `finally`.
   * Served as `application/octet-stream` with RFC 5987 encoded `Content-Disposition: attachment; filename*=UTF-8''...`.
   * No token in query strings (`?token=...`). Frontend uses `fetch` with `Authorization` header to receive Blobs.
9. **Reverse Proxy & Injection Hardening:**
   * `app.set('query parser', 'simple')` + strict Zod parsing to prevent Express `qs` object injection into Prisma.
   * Server bound to `127.0.0.1:5000` with `trust proxy 1`, extracting IP from `cf-connecting-ip`.
   * Dual rate limiters: Global IP (100 req/min) + Login (5 attempts/15min) keyed on composite `ip + '_' + email`.
   * Dummy bcrypt compare on non-existent emails to equalize response times.

---

## 4. Database Schema & Dual PostgreSQL Roles

### Dual Role Architecture
1. **Migration Role (`trustvault_admin`):** Full DDL permissions for Prisma migrations.
2. **Application Role (`trustvault_app`):** Runtime role used by Node.js server:
   ```sql
   -- Run once as superuser:
   CREATE USER trustvault_app WITH PASSWORD '<APP_ROLE_PASSWORD>';
   GRANT CONNECT ON DATABASE trustvault TO trustvault_app;
   GRANT USAGE ON SCHEMA public TO trustvault_app;
   GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO trustvault_app;
   
   -- Lockdown AuditLog:
   REVOKE UPDATE, DELETE, TRUNCATE ON "AuditLog" FROM trustvault_app;
   GRANT SELECT, INSERT ON "AuditLog" TO trustvault_app;

   -- Mutation-prevention trigger:
   CREATE OR REPLACE FUNCTION reject_audit_mutation()
   RETURNS TRIGGER AS $$
   BEGIN
     RAISE EXCEPTION 'AuditLog rows are strictly immutable. UPDATE and DELETE are prohibited.';
   END;
   $$ LANGUAGE plpgsql;

   CREATE TRIGGER trg_prevent_audit_mutation
   BEFORE UPDATE OR DELETE ON "AuditLog"
   FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();
   ```

### Complete Prisma Schema (`prisma/schema.prisma`)
```prisma
datasource db {
  provider = "postgresql"
  url      = env("DATABASE_URL")
}

generator client {
  provider = "prisma-client-js"
}

enum Role {
  ADMIN
  OWNER
  VIEWER
}

enum PermissionLevel {
  READ
  EDIT
}

enum AuditStatus {
  SUCCESS
  DENIED
  FAILED
}

model User {
  id           String               @id @default(uuid())
  email        String               @unique
  passwordHash String
  name         String
  role         Role                 @default(VIEWER)
  isActive     Boolean              @default(true)
  tokenVersion Int                  @default(1)
  createdAt    DateTime             @default(now())
  updatedAt    DateTime             @updatedAt
  documents    Document[]           @relation("DocumentOwner")
  permissions  DocumentPermission[] @relation("UserPermissions")
  grantedPerms DocumentPermission[] @relation("GrantedBy")

  @@index([email])
}

model Document {
  id               String               @id @default(uuid())
  title            String
  description      String?
  originalFilename String
  storedFilename   String               // Current active file blob UUID on disk
  fileSize         Int
  mimeType         String
  category         String
  fileHash         String               // SHA-256 of current active blob
  isDeleted        Boolean              @default(false)
  deletedAt        DateTime?
  ownerId          String
  owner            User                 @relation("DocumentOwner", fields: [ownerId], references: [id], onDelete: Restrict)
  versions         DocumentVersion[]
  permissions      DocumentPermission[]
  createdAt        DateTime             @default(now())
  updatedAt        DateTime             @updatedAt

  @@index([ownerId])
  @@index([category])
  @@index([isDeleted])
}

model DocumentVersion {
  id             String   @id @default(uuid())
  documentId     String
  document       Document @relation(fields: [documentId], references: [id], onDelete: Restrict)
  versionNumber  Int
  storedFilename String   // Preserved previous blob UUID
  fileSize       Int
  fileHash       String
  uploadedById   String
  createdAt      DateTime @default(now())

  @@unique([documentId, versionNumber])
}

model DocumentPermission {
  id              String          @id @default(uuid())
  documentId      String
  document        Document        @relation(fields: [documentId], references: [id], onDelete: Cascade)
  userId          String
  user            User            @relation("UserPermissions", fields: [userId], references: [id], onDelete: Cascade)
  permissionLevel PermissionLevel
  expiresAt       DateTime?
  grantedById     String
  grantedBy       User            @relation("GrantedBy", fields: [grantedById], references: [id], onDelete: Restrict)
  grantedAt       DateTime        @default(now())

  @@unique([documentId, userId])
  @@index([userId, documentId])
}

model AuditLog {
  id             String      @id @default(uuid())
  sequenceNumber BigInt      @unique
  timestamp      DateTime    // Explicitly set by Node.js to millisecond precision
  action         String
  userId         String?     // Plain unconstrained string
  userEmail      String?     // Covered by HMAC hash
  documentId     String?     // Plain unconstrained string (no FK constraint)
  documentTitle  String?     // Covered by HMAC hash
  status         AuditStatus
  ipAddress      String
  userAgent      String
  details        String
  previousHash   String
  hash           String

  @@index([sequenceNumber])
  @@index([timestamp])
}
```

---

## 5. Endpoints & Route Access Matrix

| Method | Endpoint | Allowed Roles | Enforcement Mechanism | Failure Status |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Public | Zod validation. Forces `VIEWER`. Uniform response | 400 |
| `POST` | `/api/auth/login` | Public | Rate-limited (IP + email). Dummy bcrypt compare | 401 |
| `POST` | `/api/auth/logout` | Authenticated | Increments user `tokenVersion` | 401 |
| `GET` | `/api/auth/me` | Authenticated | Verifies JWT & DB `tokenVersion` | 401 |
| `GET` | `/api/users/lookup` | Authenticated | Exact-match `?email=...`. Rate limited | 404 |
| `PATCH`| `/api/admin/users/:id/role` | `ADMIN` only | Updates role, bumps target `tokenVersion`, audits | 403 |
| `POST` | `/api/admin/users/:id/deactivate` | `ADMIN` only | Sets `isActive=false`, bumps `tokenVersion` | 403 |
| `GET` | `/api/admin/documents` | `ADMIN` only | Metadata-only list across all documents | 403 |
| `POST` | `/api/documents` | `OWNER`, `ADMIN` | Multer + magic bytes + extension whitelist | 400 / 403 |
| `GET` | `/api/documents` | Authenticated | Scoped by `visibleDocumentsWhere(user)` | Empty array |
| `GET` | `/api/documents/search` | Authenticated | Scoped by `visibleDocumentsWhere(user)`. Escapes `%` and `_` | Empty array |
| `GET` | `/api/documents/:id` | Authenticated | `loadDocumentFor(user, id, 'read')` | **404** (unknown) |
| `GET` | `/api/documents/:id/download` | Authenticated | `loadDocumentFor(user, id, 'download')`. Fail-closed audit | **404** (unknown) |
| `PUT` | `/api/documents/:id` | Authenticated | `loadDocumentFor(user, id, 'edit')`. Saves old version | **404** / **403** (read-only) |
| `GET` | `/api/documents/:id/versions` | `OWNER` only | Returns version history. Protects redactions | **403** (non-owner) |
| `DELETE`| `/api/documents/:id` | `OWNER`, `ADMIN` | `loadDocumentFor(user, id, 'delete')`. Soft-delete | **404** / **403** |
| `POST` | `/api/documents/:id/permissions` | `OWNER` only | `loadDocumentFor(user, id, 'manage_permissions')` | **403** (non-owner) |
| `DELETE`| `/api/documents/:id/permissions/:userId` | `OWNER` only | `loadDocumentFor(user, id, 'manage_permissions')` | **403** (non-owner) |
| `GET` | `/api/admin/audit-logs` | `ADMIN` only | Paginated audit trail | 403 |
| `GET` | `/api/admin/audit-verify` | `ADMIN` only | Validates HMAC chain & external anchor | 403 |

---

## 6. Audit Hash Calculation Function

```typescript
// src/services/auditService.ts
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
}, secret: string): string {
  // Deterministic canonical JSON with sorted keys
  const canonicalString = JSON.stringify({
    action: entry.action,
    details: entry.details,
    documentId: entry.documentId ?? null,
    documentTitle: entry.documentTitle ?? null,
    id: entry.id,
    ipAddress: entry.ipAddress,
    previousHash: entry.previousHash,
    sequenceNumber: entry.sequenceNumber.toString(), // Prevents BigInt JSON crash
    status: entry.status,
    timestamp: entry.timestamp.toISOString(),        // Explicit millisecond precision
    userAgent: entry.userAgent,
    userEmail: entry.userEmail ?? null,
    userId: entry.userId ?? null
  });

  return crypto.createHmac('sha256', secret).update(canonicalString).digest('hex');
}
```

---

## 7. Immediate Next Steps on Any Machine

When you resume on your other machine:
1. **Pull the Repository:**
   ```bash
   git pull origin master
   ```
2. **Inspect Documentation:**
   - [THREATS.md](file:///c:/Users/suren/OneDrive/Documents/Snovasys/THREATS.md) (23 attack vectors cataloged)
   - [PROMPTS.md](file:///c:/Users/suren/OneDrive/Documents/Snovasys/PROMPTS.md) (5 genuine oversight entries with commit links)
   - [CONTEXT_HANDOVER.md](file:///c:/Users/suren/OneDrive/Documents/Snovasys/CONTEXT_HANDOVER.md) (This file)
3. **Step 1 — Initialize Backend & Dependencies:**
   Install dependencies:
   `express`, `@prisma/client`, `zod`, `bcrypt`, `jsonwebtoken`, `multer`, `helmet`, `cors`, `express-rate-limit`, `file-type`
   Dev dependencies:
   `typescript`, `@types/node`, `@types/express`, `@types/bcrypt`, `@types/jsonwebtoken`, `@types/multer`, `prisma`, `jest`, `supertest`, `eslint`
4. **Step 2 — Set Up ESLint Boundary Rule:**
   Configure `.eslintrc.json` with `no-restricted-imports` banning `@prisma/client` outside `src/dal/`.
5. **Step 3 — Run PostgreSQL Setup & Prisma Migrations:**
   Create PostgreSQL database, execute dual-role SQL script, and run `npx prisma migrate dev`.
6. **Step 4 — Implement Audit Service:**
   Write `src/services/auditService.ts` with HMAC-SHA256, `pg_advisory_xact_lock(749281)`, and external anchor generation.
7. **Step 5 — Implement Data Access Layer:**
   Write `src/dal/documentDal.ts` with `loadDocumentFor` and `visibleDocumentsWhere`.
8. **Step 6 — Wire Express Routes & Early Cloudflare Deployment:**
   Deploy skeleton to verify live HTTPS domain and proxy headers.
