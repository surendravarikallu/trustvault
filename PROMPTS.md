# TrustVault — AI Interaction & Oversight Log (PROMPTS.md)

> **Evaluation Criteria:** Demonstrates human engineering oversight, critical security analysis, and active intervention when AI generated flawed designs, vulnerabilities, or specification oversights.  
> Every entry records the original AI proposal, the specific vulnerability or flaw identified by the developer, the architectural fix applied, and the corresponding Git commit reference.

---

### Entry 1: Redundant Authorization Layers Defeating Mutation Testing
* **Date:** 2026-10-19
* **Topic:** Authorization Architecture & Mutation Resistance
* **What I Asked:**  
  "Design a defense-in-depth authorization system for document access so that if the primary gatekeeper is bypassed, secondary defenses protect the files."
* **What the AI Proposed:**  
  The AI proposed a "5 independent layers" architecture:
  - Layer 1: Route middleware (`can()`).
  - Layer 2: Controller re-verification calling the same `verifyAccess()` check.
  - Layer 3: Storage opacity (UUID filenames on disk).
  - Layer 4: SQL query scoping.
  - Layer 5: Audit logging.
* **What Was Wrong (Developer Intervention):**  
  1. **Failed Mutation Testing:** The evaluation brief specifically states that judges remove one authorization check and rerun test suites. Because Layer 1 and Layer 2 ran identical logic, removing the route middleware still left the controller check active — meaning tests stayed green and failed to prove the route middleware was tested.
  2. **False Claims of Defense-in-Depth:** Storage opacity is security through obscurity (once a DB record is read, the UUID is known), and audit logging is forensic detection, not prevention. Calling them "independent authorization layers" was an indefensible overclaim.
  3. **Synthetic Test:** The AI wrote a test `middleware_bypass_still_blocked` using a fake mocked route rather than real production routes.
* **What I Did Instead:**  
  Replaced redundant checks with **Structural Impossibility via a single Data Access Layer (`src/dal/documentDal.ts`)**:
  - Implemented `loadDocumentFor(user, docId, action, reqContext)` as the sole path to retrieve document records and file paths.
  - Banned direct `@prisma/client` imports in controllers via an ESLint `no-restricted-imports` rule.
  - Removing the authorization check in `loadDocumentFor()` causes real route tests to fail immediately (RED), satisfying mutation testing.
* **Commit:** [`8ef879e` - Architecture & Threat Specification](https://github.com/surendravarikallu/trustvault/commit/8ef879e)

---

### Entry 2: Audit Foreign Key Constraint Creating Existence Oracles and Mutating History
* **Date:** 2026-10-19
* **Topic:** Cryptographic Audit Ledger & Relational Integrity
* **What I Asked:**  
  "Create the Prisma schema for the AuditLog table, linking documents and users to audit events."
* **What the AI Proposed:**  
  The AI defined `AuditLog.documentId` as a Foreign Key referencing `Document.id` with `onDelete: SetNull`:
  ```prisma
  documentId String?
  document   Document? @relation(fields: [documentId], references: [id], onDelete: SetNull)
  ```
* **What Was Wrong (Developer Intervention):**  
  1. **Existence Oracle / 500 Crash:** When an unauthenticated attacker or adversary probes a non-existent UUID (e.g. `GET /documents/00000000-0000-0000-0000-000000000000/download`), attempting to insert that non-existent UUID into `AuditLog` violates the Foreign Key constraint. This causes a database error (500) or drops the log, creating a side-channel existence oracle.
  2. **Hash Chain Invalidation:** When a document is legitimately deleted, PostgreSQL's `ON DELETE SET NULL` executes an `UPDATE` on all historical audit rows, changing `documentId` to `NULL`. This mutates past audit data, permanently breaking cryptographic hash verification for historical events.
* **What I Did Instead:**  
  - Removed the Foreign Key constraint entirely. Stored `documentId` as an unconstrained plain string/UUID snapshot alongside `documentTitle`.
  - Non-existent UUID probes log safely without constraint violations.
  - Historical rows remain strictly immutable upon document deletion.
* **Commit:** [`09130fd` - Enforced DAL, HMAC-SHA256 Audit Ledger, and Test Matrix](https://github.com/surendravarikallu/trustvault/commit/09130fd)

---

### Entry 3: Unhashed Columns in Audit Ledger & BigInt JSON Crash
* **Date:** 2026-10-19
* **Topic:** Cryptographic Hash Integrity & Type Serialization
* **What I Asked:**  
  "Implement the HMAC hash chain calculation function for AuditLog rows."
* **What the AI Proposed:**  
  The AI implemented a hash function that serialized a subset of columns:
  ```typescript
  function computeHash(entry, prevHash) {
    return sha256(JSON.stringify({
      seq: entry.sequenceNumber,
      action: entry.action,
      userId: entry.userId,
      docId: entry.documentId,
      status: entry.status,
      prevHash
    }));
  }
  ```
* **What Was Wrong (Developer Intervention):**  
  1. **Omitted Columns (Tamper Vulnerability):** The hash omitted `id`, `userEmail`, `documentTitle`, `ipAddress`, `userAgent`, and `details`. A database attacker could alter `documentTitle` or `userEmail` without breaking the hash chain.
  2. **BigInt Serialization Crash:** `AuditLog.sequenceNumber` was typed as `BigInt`. Calling `JSON.stringify` on an object containing a `BigInt` throws a runtime `TypeError: Do not know how to serialize a BigInt`.
  3. **Microsecond Timestamp Drift:** Relying on PostgreSQL `DEFAULT now()` stores timestamps with microsecond precision, while Node.js `Date` reads millisecond precision, leading to deterministic hash mismatch during verification.
* **What I Did Instead:**  
  - Included all 13 table columns in a canonical JSON payload.
  - Converted `sequenceNumber.toString()` before JSON serialization.
  - Set timestamps explicitly in Node.js ISO format prior to insertion.
  - Switched from standard SHA-256 to **HMAC-SHA256** using an external secret key (`AUDIT_HMAC_SECRET`).
* **Commit:** [`09130fd` - Enforced DAL, HMAC-SHA256 Audit Ledger, and Test Matrix](https://github.com/surendravarikallu/trustvault/commit/09130fd)

---

### Entry 4: JWT Role Drift & Missing Instant Demotion Revocation
* **Date:** 2026-10-19
* **Topic:** Session Management & Instant Revocation
* **What I Asked:**  
  "Design JWT authentication for users including Admin and Viewer roles."
* **What the AI Proposed:**  
  The AI encoded `userId`, `email`, and `role` inside the JWT payload with an 8-hour expiration. Route middleware read `req.user.role` directly from the decoded token.
* **What Was Wrong (Developer Intervention):**  
  1. **Privilege Demotion Lag:** If an Admin is demoted to Viewer or an employee is terminated, their stolen or issued JWT remains valid for up to 8 hours. The user retained administrative privileges because the token was stateless.
  2. **Specification Violation:** The brief specifically noted the vulnerability: *"Someone leaves and their link still works"*.
* **What I Did Instead:**  
  - Added a `tokenVersion: Int @default(1)` column to the `User` model.
  - Added `PATCH /api/admin/users/:id/role` and user deactivation endpoints that increment `tokenVersion`.
  - Auth middleware checks the active user record and verifies `token.tokenVersion === dbUser.tokenVersion` on every request.
  - Demotion or logout invalidates all existing tokens instantly.
* **Commit:** [`09130fd` - Enforced DAL, HMAC-SHA256 Audit Ledger, and Test Matrix](https://github.com/surendravarikallu/trustvault/commit/09130fd)

---

### Entry 5: Missing Upload Validation, Role Hierarchy Drop, and Object Query Injection
* **Date:** 2026-10-19
* **Topic:** Specification Completeness & Defense Hardening
* **What I Asked:**  
  "Review the simplified specification and check for missing requirements from the evaluation brief."
* **What the AI Proposed:**  
  During an earlier simplification pass, the AI:
  - Reduced the `Role` enum to only `ADMIN` and `VIEWER`, leaving out `OWNER` and allowing any user to upload files.
  - Dropped upload file-validation safeguards (magic bytes, extension whitelisting, temp file cleanup).
  - Left Express's default `qs` query parser enabled without sanitization.
* **What Was Wrong (Developer Intervention):**  
  1. **Role Spec Contradiction:** The brief mandates three distinct roles: Administrator, Document Owner, and Viewer. Removing `OWNER` broke the role hierarchy.
  2. **File Upload Vulnerability:** Uploading disguised executables (e.g. `malware.exe` renamed to `file.pdf`) would be accepted without magic byte inspection.
  3. **Express `qs` Object Injection:** Express parses `?owner[not]=x` into an object, which can manipulate Prisma `WHERE` filters if passed unvalidated.
* **What I Did Instead:**  
  - Restored `OWNER` in the `Role` enum. Public registration creates `VIEWER`; only `OWNER` or `ADMIN` can upload documents.
  - Added full upload validation with buffer magic bytes (`src/utils/fileSignature.ts`), extension whitelist, null-byte checks, and Multer temp-file unlinking on failure.
  - Configured `app.set('query parser', 'simple')` and wrapped all inputs with strict Zod schemas.
* **Commit:** [`09130fd` - Enforced DAL, HMAC-SHA256 Audit Ledger, and Test Matrix](https://github.com/surendravarikallu/trustvault/commit/09130fd)

---

### Entry 6: ESLint Boundary Enforcement Catching Prisma Imports in Controllers
* **Date:** 2026-10-19
* **Topic:** Strict Architectural Boundary Enforcement via Automated Linting
* **What I Asked:**  
  "Write the Express controllers for auth, documents, permissions, and admin operations."
* **What the AI Proposed:**  
  The AI directly imported `@prisma/client` in several controllers and middleware:
  ```typescript
  import { Role, PermissionLevel, AuditStatus } from '@prisma/client';
  ```
* **What Was Wrong (Developer Intervention):**  
  The automated ESLint rule `no-restricted-imports` immediately failed the build with 6 errors:
  `'@prisma/client' import is restricted from being used. Direct Prisma database imports are strictly prohibited outside src/dal/ and prisma/.`
  Even importing enums from `@prisma/client` creates an implicit dependency on the database client, tempting future developers to import Prisma types or instantiate direct query clients in controllers.
* **What I Did Instead:**  
  - Created `src/dal/types.ts` within the Data Access Layer to export all domain types and enums (`Role`, `PermissionLevel`, `AuditStatus`, `UserContext`, `RequestContext`).
  - Rewrote all controllers, middleware, and routes to import strictly from `src/dal/types`.
  - Re-ran `npm run lint` and `npm run build` to verify 100% compliance with zero restricted imports.
* **Commit:** [`09130fd` - Enforced DAL, HMAC-SHA256 Audit Ledger, and Test Matrix](https://github.com/surendravarikallu/trustvault/commit/09130fd)
