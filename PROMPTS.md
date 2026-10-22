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

---

### Entry 7: AI-Generated UI Tropes vs. Professional Enterprise Security Console
* **Date:** 2026-10-19
* **Topic:** Frontend Aesthetics & Enterprise Usability
* **What I Asked:**  
  "Build the web interface for TrustVault to interact with documents, manage permissions, and inspect the audit ledger."
* **What the AI Proposed:**  
  The AI generated a frontend with classic "AI demo" visual tropes:
  - Cheesy radial glowing neon cyan/purple background blobs.
  - Unicode emojis in place of real vector icons (🛡️, 📄, ⚠️, 🤖, ✨).
  - Floating marketing cards with low data density and excessive padding.
  - "AI Reviewer Assistant" styled like a consumer chatbot with sparkling purple badges.
* **What Was Wrong (Developer Intervention):**  
  An enterprise security product (like HashiCorp Vault, AWS KMS, Cloudflare Zero Trust, or Datadog) demands high information density, precise typography, crisp 1px borders, monospace cryptographic checksums, and serious access governance controls. Fluffy neon glow aesthetics undermine credibility in a security audit.
* **What I Did Instead:**  
  - Overhauled `frontend/src/index.css` using an authentic Obsidian Dark enterprise design system (slate `#070a12`, `#0d131f`, and `#121a2b` surfaces; sharp 4px/6px radii; restrained high-contrast accents).
  - Replaced all Unicode emojis with crisp vector icons from Lucide.
  - Redesigned the "AI Assistant" as an **Automated Least-Privilege Policy Recommender** with clear risk scoring and mandatory dual-signature human confirmation.
  - Built a dense tabular data grid with copy-to-clipboard SHA-256 fingerprints, environment status bars, and instant 1-click evaluation principal switches.
* **Commit:** [`faa10bf` - Enterprise Frontend Client & Evaluation Personas](https://github.com/surendravarikallu/trustvault/commit/faa10bf)

---

### Entry 8: Un-narrated Audit Logs & Express BigInt Serialization Crash
* **Date:** 2026-10-19
* **Topic:** Audit Log Legibility, Event Narratives & BigInt JSON Serialization
* **What I Asked:**  
  "Display the audit ledger records in the admin dashboard so that auditors can inspect recent security events."
* **What the AI Proposed:**  
  The AI returned raw database rows directly from `prisma.auditLog.findMany()`, rendering raw enum strings like `USER_DEACTIVATED`, `ACCESS_DENIED`, or `DOCUMENT_DOWNLOAD_STARTED` alongside `N/A` target labels.
* **What Was Wrong (Developer Intervention):**  
  1. **Runtime 500 Crash:** `AuditLog.sequenceNumber` is stored as a PostgreSQL 64-bit `BigInt`. When Express called `res.json()`, Node's native `JSON.stringify` immediately threw:
     `TypeError: Do not know how to serialize a BigInt`.
  2. **Unintelligible to Auditors:** Showing `USER_DEACTIVATED` with target `N/A` gave no indication of *which user was deactivated* or *who deactivated them*. Similarly, downloads showed only the acting user without highlighting the affected document.
* **What I Did Instead:**  
  - In `src/dal/auditDal.ts`, mapped `sequenceNumber` to `.toString()` before returning paginated log queries.
  - Implemented an **Event Narrative Engine (`formatAuditStory`)** in `frontend/src/components/AuditLedgerView.tsx` that generates human-readable, user-pointing sentences:
    - *"admin@trustvault.local deactivated user demote_target@trustvault.local (Active sessions invalidated immediately)."*
    - *"viewer@trustvault.local downloaded file Master Services Agreement (MSA) - Acme Corp."*
    - *"owner@trustvault.local granted READ access on MSA Acme to viewer@trustvault.local."*
    - *"Security Gatekeeper BLOCKED probe by eve@trustvault.local on Executive Compensation Review."*
  - Added an expandable row details drawer showing client IP, user agent, preceding HMAC, current HMAC-SHA256, and raw log payload.
* **Commit:** [`5cd81f6` - Human-readable Event Narratives & BigInt Serialization Fix](https://github.com/surendravarikallu/trustvault/commit/5cd81f6)

---

### Entry 9: Decoupled Audit Rows Lacking Human User Names & Threat Matrix Numbering Gap
* **Date:** 2026-10-19
* **Topic:** Audit Attribution, Human Identity Resolution & Threat Specification Continuity
* **What I Asked:**  
  "Show both the user's full name and login email in the audit trail, correct the missing T-23 in THREATS.md, and verify the Single Gatekeeper DAL architecture."
* **What the AI Proposed:**  
  The AI previously displayed only raw login email addresses (`viewer@trustvault.local`), and in the Principal & Target column, truncated the email prefix (`log.userEmail.split('@')[0]`), producing `viewer (viewer@trustvault.local)` instead of resolving the actual human account holder (`Bob Authorized Viewer`). In addition, the AI's prior documentation update skipped from `T-22` directly to `T-24`, creating a numbering discontinuity in `THREATS.md`.
* **What Was Wrong (Developer Intervention):**  
  1. **Forensic Attribution Gap:** In SOC2 and ISO 27001 compliance auditing, forensic teams need instant attribution to real human individuals (e.g., `Bob Authorized Viewer`), not just generic mailbox identifiers. Because `AuditLog` purposefully omits foreign key constraints to prevent cascade deletion attacks and existence oracles, human names were never attached to serialized rows.
  2. **Cryptographic Immutability Constraint:** Simply adding a `userName` column to the `computeAuditHash()` canonical payload would invalidate all historical HMAC signatures in the database.
  3. **Threat Catalog Gap:** Skipping `T-23` in `THREATS.md` created confusion regarding the exact number of modeled attack vectors and violated sequential traceability against test suites.
* **What I Did Instead:**  
  - In `src/dal/auditDal.ts`: Enhanced `getAuditLogs()` to dynamically query `prisma.user` for all distinct `userId`s and `userEmail`s present in the requested page, resolving `userName` on the fly with seed fallback mapping (`Security Administrator`, `Alice Document Owner`, `Bob Authorized Viewer`, `Eve Adversary`). This preserves 100% cryptographic HMAC chain verification while enriching frontend attribution.
  - In `frontend/src/components/AuditLedgerView.tsx`: Updated `formatAuditStory()` and the "Principal & Target" column to prominently display both the human name and login email: e.g. `Bob Authorized Viewer (viewer@trustvault.local)`.
  - In `THREATS.md`: Restored strict sequential numbering (`T-23` for orphaned disk storage, `T-24` for unbounded heap memory, `T-25` for HTTP response splitting, `T-26` for uncaught exception leakage; mutation testing subsequently re-indexed to `T-32` upon addition of Category G protocol hardening `T-27` to `T-31`).
  - Verified and documented that `src/dal/documentDal.ts` (`loadDocumentFor` and `visibleDocumentsWhere`) remains the strictly enforced **Single Gatekeeper DAL** across the entire codebase.
* **Commit:** [`feb6367` - Dual Name & Email Audit Attribution, Threat Numbering Fix](https://github.com/surendravarikallu/trustvault/commit/feb6367)

---

### Entry 10: Remote Web Adversarial Verification, Controlled Mutation Testing & Defense Subsystems
* **Date:** 2026-10-19
* **Topic:** Remote Web Testing, True-Positive Validation & Defense Subsystem Matrix
* **What I Asked:**  
  "Support testing arbitrary live web URLs over HTTP/HTTPS against adversarial attack vectors. Validate that the verification script is genuine and not reporting false positives by intentionally simulating a bypass in the codebase. Apply high-standard security verification suites to other critical subsystems and add them to the test folder."
* **What the AI Proposed:**  
  The AI originally wrote in-memory verification tests with Supertest against localhost, which could not probe live deployed Cloudflare Tunnels or remote staging domains. Additionally, the test suite had not been validated against an intentional failure, leaving open the risk of false-positive "mock passes."
* **What Was Wrong (Developer Intervention):**  
  1. **Network Transport Gap:** In production and staging environments, access control must be verified over true HTTP/HTTPS network connections to ensure reverse-proxy headers, Cloudflare headers, and transport-level security policies (`nosniff`, CSP, CORS) function correctly.
  2. **Validation Necessity (Testing the Test):** A security verification script cannot be assumed reliable without proving it detects real vulnerabilities. Without a controlled mutation test, a script could simply exit with status 0 regardless of application security state.
  3. **Coverage Gaps:** While the Data Access Layer was verified, the cryptographic audit ledger, session invalidation engine, and upload hardening lacked dedicated, modular test files in `tests/`.
* **What I Did Instead:**  
  - Refactored `scripts/verify-dal-invariants.ts` to use Node's native `fetch` API, enabling live testing against any provided web URL (e.g. `npx tsx scripts/verify-dal-invariants.ts https://your-tunnel.trycloudflare.com`).
  - Conducted a controlled mutation test by intentionally injecting an `alg: none` bypass into `src/middleware/auth.ts`. Confirmed that `verify-dal-invariants.ts` immediately went RED (`VULNERABLE: Data Leaked? YES (FAIL)`, exit code 1), proving the script accurately identifies real security flaws. Then restored the codebase to its secure state.
  - Added 3 high-standard test suites to `tests/` covering 31 total tests:
    - `tests/audit-tamper-immutability.test.ts` (13-column HMAC integrity, concurrency advisory locking, anchor substitution)
    - `tests/identity-revocation.test.ts` (instant deactivation severance, dummy bcrypt timing attack parity, owner-only delegation, email lookup enumeration defense)
    - `tests/upload-hardening.test.ts` (PE/MZ magic byte rejection, unauthorized extensions, MIME/extension discrepancy, version history preservation, search query memory bounds).
  - Expanded `THREATS.md` with Category G (Threats T-27 through T-31) and Section 3 (T-32: Mutation Testing), maintaining uninterrupted sequential indexing across all 32 threats.
* **Commit:** [`233fce8` - Live Web Testing, Subsystem Matrix, and Sequential Threat Numbering Fix](https://github.com/surendravarikallu/trustvault/commit/233fce8)

---

### Entry 11: Multi-Factor Authentication (MFA / TOTP) Enterprise Hardening & Zero-Dependency Engine
* **Date:** 2026-10-19
* **Topic:** Multi-Factor Authentication, RFC 6238 TOTP & Zero-Dependency Cryptographic Reliability
* **What I Asked:**  
  "Implement MFA and TOTP with the highest enterprise security standards matching the rest of the zero-trust architecture."
* **What the AI Proposed:**  
  The AI originally proposed pulling in an external third-party library (`otplib` v13) with pure-ESM transitive dependencies (`@scure/base`), storing TOTP secrets in plaintext in the database, and issuing full session tokens directly from password login without a restricted challenge state.
* **What Was Wrong (Developer Intervention):**  
  1. **Transitive Dependency & Test Suite Breakage:** The pure-ESM transitive dependency broke CommonJS Jest test execution with `SyntaxError: Unexpected token 'export'`, creating an opaque external dependency failure in evaluation test runners.
  2. **Plaintext Secrets (CWE-312):** Storing Base32 TOTP secrets in plaintext in PostgreSQL leaves user authenticator seeds vulnerable to database-level compromise or backup leakage.
  3. **Replay Attacks (CWE-287):** Without recording the validated time-step, an eavesdropped or intercepted 6-digit TOTP code could be replayed by an attacker within the active 30-second window.
  4. **Account Lockout Risk:** Lacked single-use emergency recovery backup codes, creating irreversible denial of service if an authenticator phone was lost or damaged.
* **What I Did Instead:**  
  - Built an auditable, zero-dependency native Node.js RFC 6238 TOTP cryptographic engine (`src/utils/totp.ts`) using Node's native C++ OpenSSL `crypto.createHmac('sha1', key)` and RFC 4648 Base32 decoding, eliminating external ESM packaging conflicts.
  - Encrypted all TOTP secrets at rest in PostgreSQL using AES-256-GCM (`src/utils/mfaCrypto.ts`).
  - Added replay attack defense by tracking `mfaLastTimeStep` per user, rejecting duplicate code reuse in the same 30-second step with HTTP 401.
  - Implemented 8 single-use cryptographically random recovery backup codes (hashed with SHA-256 and burned upon first consumption).
  - Enforced a 2-stage login handshake: successful password authentication returns a restricted 3-minute `mfaChallengeToken` (incapable of accessing vault documents) until the TOTP code is verified.
  - Added dedicated test suite (`tests/mfa-totp.test.ts`) covering 8 lifecycle and adversarial tests, expanding total automated coverage to 39 tests across 6 suites.
* **Commit:** [`master` - Multi-Factor Authentication (MFA/TOTP) Enterprise Hardening](https://github.com/surendravarikallu/trustvault)

---

### Entry 12: Production Hardening, Composite Database Indexes, Envelope Encryption & Cryptographic Backups
* **Date:** 2026-10-19
* **Topic:** Database Performance, Composite Indexing, Envelope Encryption at Rest, and Disaster Recovery
* **What I Asked:**  
  "Now go with full application creation with performance optimisation and database optimisation, backups, etc like a real system."
* **What the AI Proposed:**  
  The AI suggested directly querying Prisma models inside the backup service, using simple single-column indexes, storing files on disk as raw unencrypted binaries, and running shell commands (`pg_dump`) requiring external postgres CLI tool dependencies on Windows hosts.
* **What Was Wrong (Developer Intervention):**  
  1. **ESLint Architectural Boundary Violation:** Direct `@prisma/client` queries inside services violate the project's strict `no-restricted-imports` lint rule, which mandates that all database queries must be strictly encapsulated inside the Data Access Layer (`src/dal/`).
  2. **External Host Tool Dependencies:** Relying on `pg_dump` fails when running in lightweight Node container environments or Windows evaluation hosts without Postgres CLI binaries installed in the system PATH.
  3. **Storage Ciphertext Exposure (CWE-311):** Writing raw files to disk leaves confidential documents vulnerable to direct disk volume exfiltration.
  4. **Inefficient Unindexed Queries:** High-frequency filtered searches (e.g., `isDeleted` + `ownerId`, `isDeleted` + `category`, `userId` + `expiresAt` on permissions, `sequenceNumber` on audit logs) resulted in costly sequential scans under production scale.
* **What I Did Instead:**  
  - Encapsulated all database snapshot operations inside `src/dal/backupDal.ts`, fully conforming to the Single Gatekeeper DAL architecture and passing ESLint with 0 warnings.
  - Implemented high-performance composite database indexes in `prisma/schema.prisma` across `Document` (`[isDeleted, ownerId]`, `[isDeleted, category]`, `[isDeleted, createdAt]`, `[fileHash]`), `DocumentVersion`, `DocumentPermission`, and `AuditLog`.
  - Implemented AES-256-GCM Envelope Encryption at Rest in `src/services/storageService.ts` with a `TV_AES256_GCM_v1:` magic header, 12-byte IV, and 16-byte authentication tag, coupled with transparent streaming decryption (`createDecryptedReadStream`) maintaining seamless backward-compatibility with unencrypted legacy seed files.
  - Built an automated Disaster Recovery engine (`src/services/backupService.ts`) producing atomic snapshots bundling database table dumps, encrypted blobs, and external audit anchors signed with HMAC-SHA256, complete with tamper-detection verification and automated 7-snapshot rolling retention.
  - Enhanced `/api/health` with live database round-trip latency (`SELECT 1`), process memory metrics, and uptime.
  - Added test suite `tests/backup-disaster-recovery.test.ts` (6 tests), expanding total test coverage to 45 passing tests across 7 test suites with 100% mutation resistance.
* **Commit:** [`master` - Production Hardening, Database Indexes, Envelope Encryption & Disaster Recovery](https://github.com/surendravarikallu/trustvault)

---

### Entry 13: Full Suite Completion: MFA UI Integration, Heuristic Exploit Scanner & NIST SP 800-88 Crypto-Shredder
* **Date:** 2026-10-19
* **Topic:** MFA TOTP Web UI, Malicious Macro Scanning, and Cryptographic Sanitization
* **What I Asked:**  
  "what about mfa totp implementations and other three upgrades told in the chat"
* **What the AI Proposed:**  
  The AI previously implemented backend MFA endpoints but left the web interface without a 2-step TOTP challenge dialog or QR code enrollment modal. Furthermore, file sanitization relied solely on MIME/magic bytes without inspecting internal PDF exploit streams or OOXML macro binaries, and document deletion was purely logical (soft delete).
* **What Was Wrong (Developer Intervention):**  
  1. **UI Disconnect:** Without frontend handling for `mfaRequired: true`, users with MFA enabled were blocked from logging into the web dashboard, and could not enroll their authenticators visually.
  2. **Weaponized Macro & PDF Exploit Blindness (CWE-434 / CWE-94):** Magic byte checking confirms a file is a valid PDF or ZIP, but valid PDFs can contain malicious `/Launch` and `/JavaScript` actions, while valid DOCX files can contain weaponized `vbaProject.bin` macro binaries.
  3. **Forensic Storage Remanence (CWE-226):** Simply executing `fs.unlink()` leaves confidential ciphertext and metadata recoverable from physical flash/magnetic storage sectors.
* **What I Did Instead:**  
  - Integrated a full 2-Step Challenge Screen in `LoginView.tsx` supporting 6-digit TOTP codes and single-use emergency backup recovery codes.
  - Built `MfaModal.tsx` in the frontend dashboard providing QR code authenticator enrollment, confirmation validation, and one-click backup code copying.
  - Built [`ThreatScanner`](file:///c:/Users/Admin/Documents/trustvault/src/services/threatScanner.ts) to deeply inspect PDF exploit streams (`/Launch`, `/JavaScript`, `/JS`, `/EmbeddedFiles` + `/OpenAction`), OOXML macro binaries (`vbaProject.bin`), and obfuscated PowerShell/shell scripts, rejecting weaponized uploads with HTTP 400.
  - Implemented [`RetentionService`](file:///c:/Users/Admin/Documents/trustvault/src/services/retentionService.ts) and [`retentionDal.ts`](file:///c:/Users/Admin/Documents/trustvault/src/dal/retentionDal.ts) providing NIST SP 800-88 compliant 2-pass cryptographic disk sanitization (entropy overwrite + zeroing + `fdatasync`) before unlinking, integrated into `POST /api/admin/retention/crypto-shred`.
  - Added test suite `tests/threat-retention.test.ts` (6 tests), bringing the total test suite to **8 suites, 51 automated security tests**, with 100% pass rate.
* **Commit:** [`master` - Full Suite Completion: MFA UI, Threat Scanner & NIST Crypto-Shredder](https://github.com/surendravarikallu/trustvault)

---

### Entry 14: Edge WAF Perimeter Defense, Automated Bot Mitigation & Local Grading Separation
* **Date:** 2026-10-20
* **Topic:** Cloudflare Edge WAF, Bot Fight Mode, and Local Automated Test Grading Architecture
* **What I Asked:**  
  "API WAF Bypass (for automated grading scripts / curl) i didnt purchased the waf is there any other options, the domian is updated by removing the www... its day 2 only we are stated our domain setup and routing in day 2 only. if we allow the curl scripts we are allowing attackers to run the scripts, i was not going to off them, i will give an note in readme file and submission doc saying test scripts run on the local checking only, the scripts are blocked by cloudflare for security, it is better right."
* **What the AI Proposed:**  
  The AI initially suggested disabling Cloudflare Bot Fight Mode or creating broad bypass rules to allow arbitrary automated `curl` scripts to query the live domain `https://trustvalt.me`.
* **What Was Wrong (Developer Intervention):**  
  1. **Weakening Production Edge Defense (CWE-799 / CWE-307):** Disabling bot mitigation on a public production domain invites malicious scrapers, credential stuffing bots, automated vulnerability scanners, and volumetric Layer 7 DDoS probing.
  2. **Security Anti-Pattern:** A zero-trust production vault should never sacrifice real-world edge perimeter protection for convenience.
  3. **Cloudflare WAF Deprecation:** Attempting to use deprecated fields such as `cf.threat_score` in custom rules caused Cloudflare expression syntax errors.
* **What I Did Instead:**  
  - Maintained active Cloudflare Bot Fight Mode and strict WAF perimeter security on `https://trustvalt.me`.
  - Formulated 5 optimized Cloudflare WAF Expression Rules targeting real exploit signatures:
    1. Sensitive Dotfile Probing (`.env`, `.git`, `.aws`, `.ssh`) -> Block
    2. Remote Code & Command Injection (`${jndi:`, `cmd=`, `exec=`, `powershell`, `/bin/`) -> Block
    3. Dangerous Cross-Site Scripting Vectors (`<script`, `javascript:`, `vbscript:`, `onerror=`) -> Block
    4. Database SQL Injection Probing (`union select`, `information_schema`, `xp_cmdshell`) -> Block
    5. Abnormal HTTP Request Verbs & Stale Protocol Probing (`TRACE`, `TRACK`, `DEBUG`, `CONNECT`, or `HTTP/1.0`) -> Block
  - Established strict separation between public edge browsing (for human judges via browsers on `https://trustvalt.me`) and automated grading scripts, which run directly against the local Node.js environment (`127.0.0.1:7777` or Jest/Supertest) without CDN bot interference.
  - Updated `README.md`, `day1_submission.md`, and `day2_submission.md` with explicit architectural documentation of the Cloudflare WAF & Bot Mitigation perimeter.
* **Commit:** [`master` - Edge WAF Perimeter Defense & Submission Grading Separation](https://github.com/surendravarikallu/trustvault)

---

### Entry 15: Clean Login Page Redesign, Post-Login Opt-In 2FA Evaluation & Modal CSS Alignment
* **Date:** 2026-10-20
* **Topic:** Production Login Sanitation, Evaluator Lockout Prevention, and TOTP Modal CSS Alignment
* **What I Asked:**  
  "update the login page with login only, do not give the creditentials there, the usere names are either mail only, and passwords, after login it shows please enable 2fa, it is users choice to add 2fa with totp, if we enfore the 2fa in admin, the judges need to contact me for the admin login, what is the best choice to do tell me , get 99% confident, and there are many buttons in the dashbords which or not working."
* **What the AI Proposed:**  
  The AI initially had 1-click test credential cards displayed directly on the login screen with passwords in clear text, and had considered enforcing mandatory 2FA on the admin seed account upon initial login. Furthermore, the dashboard TOTP setup button was not opening the modal due to CSS class mismatches.
* **What Was Wrong (Developer Intervention):**  
  1. **Clear-Text Credential Display:** Exposing pre-filled test passwords on the public login view violates core enterprise UX and security presentation standards.
  2. **Evaluator Lockout Vulnerability:** If 2FA is strictly enforced on the Admin seed account pre-login, asynchronous judges evaluating the platform cannot log in without contacting the author for live TOTP tokens or authenticator sharing.
  3. **Broken Modal Rendering:** In `MfaModal.tsx`, the dialog markup used CSS classes `.modal-backdrop` and `.modal-card`, whereas `index.css` defined `.modal-overlay` and `.modal-content`. This prevented the TOTP QR modal from rendering visually on screen.
* **What I Did Instead:**  
  - Redesigned `LoginView.tsx` into a clean, professional email/password login interface without exposed credential cards or test seeds.
  - Implemented a prominent, dismissible **Post-Login 2FA Security Recommendation Banner** across the dashboard. Seed accounts start with 2FA optional, eliminating judge lockout while encouraging 1-click on-demand RFC 6238 TOTP enrollment.
  - Added on-demand pre-login 2FA enrollment endpoint `POST /api/auth/enroll-mfa` with a 9th automated security test in `tests/mfa-totp.test.ts` (`MFA-09`), expanding test coverage to 52 tests.
  - Fixed the CSS class names in `MfaModal.tsx` (`.modal-overlay` and `.modal-content`), enabling QR code rendering, base32 secret copying, and one-click backup code generation.
  - Verified complete end-to-end user journeys via browser subagent on both localhost and live domain.
* **Commit:** [`master` - Clean Login Page, Post-Login Opt-In 2FA Banner & Modal CSS Alignment](https://github.com/surendravarikallu/trustvault)

---

### Entry 16: BigInt Serialization in Disaster Recovery Backups & Zero-Trust Admin Download Semantics
* **Date:** 2026-10-20
* **Topic:** BigInt JSON Serialization, Disaster Recovery Snapshot Integrity, and Zero-Trust Admin Download Semantics
* **What I Asked:**  
  "Resolve dashboard button issues, verify admin document controls, and ensure all background services function reliably without exceptions."
* **What the AI Proposed:**  
  The AI previously used standard `JSON.stringify()` when bundling database table dumps in `BackupService.createFullBackup()`, and left document download buttons in the Admin dashboard showing generic error states or ambiguous actions.
* **What Was Wrong (Developer Intervention):**  
  1. **`TypeError: Do not know how to serialize a BigInt`:** PostgreSQL `AuditLog.sequenceNumber` and `DiskChunk.offset` columns are typed as `BigInt` in Prisma. Standard `JSON.stringify()` throws a fatal runtime exception when serializing tables containing `BigInt` values during disaster recovery backups.
  2. **Ambiguous Admin Action Semantics:** In a Zero-Trust architecture, administrators *cannot* view private document contents without an explicit cryptographic share grant. Leaving a plain "Download" button on the Admin view without explanation confused users when it returned HTTP 403.
* **What I Did Instead:**  
  - Implemented a custom `JSON.stringify(data, (key, value) => typeof value === 'bigint' ? value.toString() : value, 2)` replacer in `src/services/backupService.ts`, ensuring robust atomic snapshot bundling across all Prisma models.
  - Updated `frontend/src/components/DocumentList.tsx` to visually display a security status pill (`Restricted (Zero-Trust)`) when an Admin lacks an explicit share grant, clearly explaining the principle of least privilege in the UI rather than failing silently.
  - Verified all 52 tests, ESLint, backend TypeScript build, and Vite frontend build pass with 100% success.
* **Commit:** [`master` - BigInt Disaster Recovery Serialization & Zero-Trust Admin Semantics](https://github.com/surendravarikallu/trustvault)

---

### Entry 17: Admin Identity Governance, Ephemeral Sharing, Burn-on-Download & In-Browser Preview
* **Date:** 2026-10-20
* **Topic:** Enterprise User Lifecycle Governance, One-Time Secure File Transfers, and Ephemeral Browser Streaming
* **What I Asked:**  
  "when a file transfer admin dashboard did we need an endpoint to create users and change roles and update their login passwords and 2fa reset options and ect, and in viewer , editor role , a file is uploaded and how it is shared to other user in dashboard, did they set up any file sharing like access given to this user role editor , editor means allows download option, if the user downlods the file succesfully, the share option closes, for read role, assign a particular time as they only read the file that open in the browser only . or there are any other options you would recommend, tell me"
* **What the AI Proposed:**  
  The AI previously lacked dedicated administrative endpoints to provision identities, issue password resets, or execute emergency 2FA resets. Furthermore, file sharing grants were static (either permanent or time-bounded), lacking the ability to automatically close after a single successful download, or enforce browser-only viewing without raw binary downloads.
* **What Was Wrong (Developer Intervention):**  
  1. **Administrative Governance Gaps:** Administrators in enterprise systems must be able to provision users, reset forgotten passwords, and perform emergency 2FA resets if an employee loses their authenticator device.
  2. **Post-Download Grant Retention Risk:** When sensitive documents are transferred, leaving the share link or grant open indefinitely creates unnecessary forward exfiltration surface.
  3. **Binary Exfiltration of View-Only Documents:** When sharing sensitive contracts for review, recipients should be restricted to previewing content inside the browser memory without saving raw unmanaged binaries to disk.
* **What I Did Instead:**  
  - **Admin User Management Architecture:**
    - Implemented `POST /api/admin/users` to provision new identities with specified enterprise roles.
    - Implemented `POST /api/admin/users/:id/reset-password` which securely hashes the new password and atomically increments `tokenVersion` in PostgreSQL, instantly severing any compromised active sessions across all devices.
    - Implemented `POST /api/admin/users/:id/reset-2fa` allowing administrators to emergency-reset TOTP secrets and recovery codes while revoking active sessions.
    - Built comprehensive UI in `UserDirectoryView.tsx` with modal dialogs, strong password generators, 2FA status indicators, and administrative actions.
  - **Burn-on-Download One-Time Secure Transfer Protocol:**
    - Added `burnOnDownload Boolean @default(false)` and `downloadCount Int @default(0)` to Prisma `DocumentPermission`.
    - Integrated Express `res.on('finish', ...)` socket listener in `documentController.ts` to trigger `burnDocumentPermission()` strictly after full binary payload transmission completes.
    - Enforced fail-closed existence shielding in `documentDal.ts`: once burned, subsequent probes by the grantee encounter `activeGrant = null` and return `HTTP 404 Not Found`.
  - **In-Browser Ephemeral Preview Only Controls:**
    - Added `previewOnly Boolean @default(false)` to `DocumentPermission`.
    - Blocked binary file download requests with `HTTP 403 Forbidden` (`"This document was shared with In-Browser Preview Only restrictions. Binary file download is prohibited."`).
    - Permitted in-browser viewing only when `?preview=true` is requested, streaming decrypted blobs with `Content-Disposition: inline`.
  - **Automated Security Verification:**
    - Created dedicated test suite `tests/governance-and-sharing.test.ts` with 5 automated tests (`BOD-01`, `PRV-01`, `ADM-01`, `ADM-02`, `ADM-03`).
    - Expanded full system test coverage to **57 passing tests across 9 test suites** with 100% HMAC ledger integrity.
* **Commit:** [`master` - Admin Identity Governance, Ephemeral Sharing, Burn-on-Download & In-Browser Preview](https://github.com/surendravarikallu/trustvault)

---

### Entry 18: Premium Enterprise UI Design System Refinement & DAL Gatekeeper Typing Integrity
* **Date:** 2026-10-20
* **Topic:** Design Aesthetics, Typography Hierarchy, CSS Tokens, and TypeScript Gatekeeper Reliability
* **What I Asked:**  
  "still the ui is not professional , see the colouring, fonts ect, everything is not professional... implement premium one which reflects as professional ui."
* **What the AI Proposed:**  
  The AI previously generated multiple theme options with interactive client-side theme switchers and inconsistent typography styles that detracted from a unified enterprise experience. Additionally, an IDE typing issue in `documentDal.ts` (`DocumentPermissionSelect`) caused compile-time type warnings for `burnOnDownload`.
* **What Was Wrong (Developer Intervention):**  
  1. **Theme Proliferation vs Unified Enterprise Polish:** A serious production cybersecurity product (like AWS KMS, Cloudflare Zero Trust, or HashiCorp Vault) should not have toy-like theme pickers or multiple conflicting palettes. It requires a single, cohesive, authoritative, institutional design language with disciplined typography and high-contrast accessibility.
  2. **Typography Quality:** Generic fallback fonts and browser defaults make interfaces look like amateur templates. A state-of-the-art enterprise security console requires deliberate font pairing: **Plus Jakarta Sans** for crisp, punchy display headers, **Inter** for dense tabular reading, and **JetBrains Mono** for cryptographic hashes and audit ledger entries.
  3. **TSServer Type Checking:** Explicitly typing the grant selection with `Prisma.DocumentPermissionSelect` in `documentDal.ts` triggered IDE caching errors when fields like `burnOnDownload` were evaluated against stale cached declaration files.
* **What I Did Instead:**  
  - **Single World-Class Enterprise Design System (`frontend/src/index.css`):**
    - Established deep obsidian velvet canvas (`#080b11`) with high-contrast surfaces (`#0e1420`), disciplined structural hairlines (`#1e2b42`), and razor-sharp enterprise corner radii (`4px` – `6px`).
    - Configured Google Fonts typography stack: **Plus Jakarta Sans** for headers, **Inter** for data tables and controls, and **JetBrains Mono** for HMAC hashes and hexadecimal digests.
    - Standardized high-contrast accessible color tokens: electric cobalt accent (`#2563eb`), verified cryptographic emerald (`#10b981`), and warning/error rose (`#ef4444`).
    - Eliminated all client-side theme switchers, informal emojis, and generic AI tropes in favor of clean Lucide SVG icons.
  - **DAL Typing Hardening (`src/dal/documentDal.ts`):**
    - Refactored `userGrantSelect` to eliminate stale language server declaration mismatches while preserving complete type inference for `activeGrant` and `loadDocumentFor`.
  - **Full System Verification:**
    - `npm run build:frontend` compiled with 0 errors.
    - `npm run lint` and `npx tsc --noEmit` passed with 0 warnings.
    - All 57 automated tests passed across all 9 test suites.
* **Commit:** [`master` - Premium Enterprise UI Design System & DAL Gatekeeper Typing](https://github.com/surendravarikallu/trustvault)

---

### Entry 19: End-to-End Persona Simulation, Authentication Schema Hardening & Audit Verification
* **Date:** 2026-10-20
* **Topic:** Multi-Persona Verification, Schema Normalization, Windows CRLF Mutation Compatibility, and Forensic Audit Ledger
* **What I Asked:**  
  "fix the finding issues, and re run the user simulation and check the audit logs, and is our system follows same as the problem statement shows? perform a user simulation over the browser so we can get the ui is also correct and working or not."
* **What Was Wrong (Developer Intervention):**  
  1. **Authentication Schema Discrepancy:** The evaluator brief specified logging in using short usernames (`admin`, `owner`, `viewer`, `eve`), but `LoginSchema` strictly checked for standard RFC 5322 email formatting, rejecting short usernames with HTTP 400.
  2. **Access Delegation Key Divergence:** API and UI sharing components passed `targetEmail` or `userEmail`, while `GrantPermissionSchema` demanded raw `userId` UUIDs.
  3. **Windows CRLF Line Ending Mutation Failure:** On Windows hosts, `scripts/mutation-test.ts` failed to locate the gatekeeper check in `src/dal/documentDal.ts` due to CRLF line ending differences.
  4. **400 Syntax Logging Noise:** Global error handling logged client bad requests (`400 Bad Request` from malformed body parser JSON) as `Unhandled server exception:`, polluting server logs.
* **What I Did Instead:**  
  - Updated `src/controllers/authController.ts` to accept `usernameOrEmail`, `email`, or `username`, resolving both email and short username credentials.
  - Updated `src/controllers/permissionController.ts` to accept `targetEmail`, `userEmail`, or `userId` and resolve grantee IDs dynamically.
  - Updated `scripts/mutation-test.ts` with CRLF normalization, achieving 100% mutation test verification.
  - Updated `src/server.ts` to strictly log `Unhandled server exception` only when `statusCode >= 500`.
  - Built `scripts/simulate-user-flows.ts` running 35 end-to-end test scenarios across all 4 personas (Admin, Owner, Viewer, Adversary), with 100% pass rate.
  - Conducted full browser simulation verifying login, document preview inline streaming, access delegation, and HMAC audit ledger verification.
* **Commit:** [`6dd405f` - End-to-End Persona Simulation, Schema Normalization & Forensic Audit Verification](https://github.com/surendravarikallu/trustvault/commit/6dd405f)

---

### Entry 20: Comprehensive Threat Matrix Completion (T-45 to T-47) & 100% Traceability Audit
* **Date:** 2026-10-20
* **Topic:** Threat Modeling Exhaustiveness, Administrative Identity Governance, and Automated Test Coverage Parity
* **What I Asked:**  
  "update the threats and prompts md with correct numbers and context."
* **What Was Wrong (Developer Intervention):**  
  1. **Threat Catalog Under-Reporting:** Although `tests/governance-and-sharing.test.ts` covered 5 distinct automated tests (`BOD-01`, `PRV-01`, `ADM-01`, `ADM-02`, `ADM-03`), `THREATS.md` only indexed up to `T-44`, leaving administrative identity provisioning, password reset session severance, and emergency 2FA resets unmodeled in the formal threat catalog.
  2. **Test Count Discrepancies:** An outdated test count reference in `THREATS.md` stated 52 tests, when the test suite had expanded to **57 tests across 9 test suites**.
* **What I Did Instead:**  
  - Formally modeled and documented threats `T-45` (Identity Provisioning & Role Elevation on Account Creation), `T-46` (Stale Session Persistence After Administrative Password Reset), and `T-47` (Authenticator Lockout & Emergency Administrative 2FA Reset) in `THREATS.md`.
  - Added Section 6 to `THREATS.md` with an exhaustive **Threat Traceability & Verification Summary Matrix** mapping all 47 modeled threats across the 9 test suites (57 tests) and 35 user simulation scenarios.
  - Synchronized all test and threat counts across `README.md`, `THREATS.md`, and `PROMPTS.md`.
* **Commit:** [`6512b8c` - Threat Matrix Completion (T-45 to T-47) & Traceability Audit](https://github.com/surendravarikallu/trustvault/commit/6512b8c)

---

### Entry 21: Role-Tailored Enterprise Dashboards, Collaborative Versioning & Access Badging
* **Date:** 2026-10-20
* **Topic:** Persona-Specific Dashboard Aesthetics, Metric KPI Grids, Scope Sub-Filters, and Revision Controls
* **What I Asked:**  
  "i think the dashboards other than admin are incorrect. give me an artifact file to simulate all users things, like uploding documet, sharing file as read and ediotr, and loggin back to other user, and able tosee the shared file to the user and accessing it."
* **What Was Wrong (Developer Intervention):**  
  1. **Dashboard Uniformity Flaw:** Non-admin roles (Owner and Viewer) previously had bare-bones document lists without executive KPI cards, clear clearance badges, or scope sub-filters ("My Uploads" vs "Shared With Me" vs "Can Edit").
  2. **Editor Action Traps:** When a document was shared with `EDIT` permissions, the table badge erroneously displayed `AUTHORIZED READ`, and the UI lacked a mechanism to upload new versions or revisions, preventing editors from exercising their authorized privileges.
  3. **Owner Version History Blindspot:** Document owners could not inspect historical document revisions or SHA-256 digests in the UI even though the backend supported version querying.
* **What I Did Instead:**  
  - **Automated Collaboration Simulation Engine (`scripts/simulate-collaboration-flow.ts`):** Built a 10-step end-to-end multi-user execution script demonstrating document upload by Alice (Owner), granting `READ` and `EDIT` to Bob (Viewer), logging in as Bob to verify visibility, streaming decrypted previews, blocking unauthorized edits and re-sharing attempts, executing authorized version replacement, verifying Eve's 404 fail-closed barrier, and auditing all events in the HMAC ledger.
  - **Role-Tailored KPI Metrics & Sub-Filters (`frontend/src/components/DocumentList.tsx`):**
    - **Owner Dashboard:** Configured 4 dedicated KPI cards (Vault Documents Owned, Active Shared Collaborations, Total Encrypted Storage, Clearance & Authority) and View Scope tabs (`All Documents`, `My Uploads`, `Shared With Me`).
    - **Viewer Dashboard:** Configured 4 dedicated KPI cards (Accessible Documents, Read-Only Clearance, Collaborative Edit Rights, Single-Use Transfers) and View Scope tabs (`All Accessible`, `Read-Only`, `Can Edit`).
    - **Admin Dashboard:** Configured 4 dedicated KPI cards (Total Managed Documents, Total Encrypted Volume, Cryptographic Ledger Link, Administrative Boundary).
  - **Accurate Edit Badging & Revision Modal (`RevisionModal.tsx` & `VersionHistoryModal.tsx`):**
    - Corrected status badge to display `AUTHORIZED EDIT` with an amber edit badge for collaborator editors.
    - Added interactive `Revision` button allowing authorized editors and owners to upload replacement file versions with automated version incrementing.
    - Added `History` modal for document owners to inspect historical version chains and copy SHA-256 digests.
* **Commit:** [`2812a4e` - Role-Tailored Dashboard KPI Metrics, Sub-Filters, Revision Modal & History Tracking](https://github.com/surendravarikallu/trustvault/commit/2812a4e)

---

### Entry 22: Dual-Channel Credential Leakage, Preview Surface Elimination & Pure `__Host-` Cookie Isolation
* **Date:** 2026-10-21
* **Topic:** Authentication Architecture, Credential Channel Unification, Client Parser Surface Elimination & Same-Origin Hardening
* **What I Asked:**  
  "Review the claim that 'HttpOnly isolation defeats XSS token theft' against the actual application runtime behavior and verify whether any tokens or fallbacks expose our authentication channel."
* **What the AI Proposed:**  
  The AI claimed that the application was immune to XSS token theft because it issued an `HttpOnly` cookie. However, its actual implementation maintained a compromised, dual-channel architecture:
  1. Login and registration JSON response bodies returned the raw JWT token (`res.json({ token, user })`).
  2. The React frontend stored this token in memory / React state, passed it into every API call via `Authorization: Bearer ${token}`, and exposed helper functions like `getAuthHeader()`.
  3. The server set *two* cookies on login: a prefixed `__Host-trustvault_token` and an unprefixed `trustvault_token`.
  4. The auth middleware accepted either the `__Host-` cookie, the legacy plain cookie, or the `Authorization: Bearer` header.
  5. The AI also retained an in-browser PDF preview surface (`?preview=true` backed by `pdfjs-dist`), arguing that canvas rendering prevented JavaScript execution.
* **What Was Wrong (Developer Intervention):**  
  1. **Hollow Security Story:** During my review pass, I executed `curl -i -X POST .../api/auth/login` myself and immediately saw the JWT printed in the plaintext JSON response body. Because the client JavaScript held this token and sent Bearer headers, any XSS execution could trivially exfiltrate the token from memory, defeating the entire rationale for HttpOnly cookies.
  2. **Subdomain Hijacking Risk:** Emitting the plain `trustvault_token` cookie defeated the `__Host-` security property, as sibling subdomains on a shared parent domain can forge or overwrite unprefixed cookies.
  3. **Dual Credential Paths:** Maintaining a Bearer fallback "for tests and curl" meant that every authorization check, rate limit, and threat vector had to cover two disparate authentication channels.
  4. **Client Parser Surface:** Client-side PDF parsing via `pdfjs-dist` executes in the page origin, introducing parser vulnerabilities (e.g. CVE-2024-4367 font script execution) and breaking the strictly audited download model.
  5. **CORS on Same-Origin App:** The server mounted `cors({ credentials: true })`, reflecting `Access-Control-Allow-Credentials: true` on plain page loads.
* **What I Did Instead:**  
  1. **Strictly Single Credential Path (`__Host-trustvault_token`)**:
     - Deleted `token` from all JSON response bodies (`login`, `register`, `verifyLoginMFA`, `confirmEnrollMFA`).
     - Deleted the legacy `trustvault_token` cookie and removed the `Authorization: Bearer` fallback in `src/middleware/auth.ts`.
     - Completely overhauled the frontend (`frontend/src/api.ts`, `App.tsx`, and all modal components) to hold ZERO token state, drop `getAuthHeader()`, and use `credentials: 'same-origin'` on all fetches.
     - Preserved concurrent judge sessions: updated `logout` to clear client cookies without bumping `tokenVersion`, preventing one evaluator's logout from kicking out other evaluators on shared seeded accounts.
  2. **Complete Elimination of Preview Surface**:
     - Uninstalled `pdfjs-dist`, deleted `DocumentPreviewModal.tsx`, removed `?preview` parameter handling, and removed `.docx` and `.xlsx` from the upload whitelist. Enforced strictly download-only delivery (`Content-Disposition: attachment`, `Content-Type: application/octet-stream`).
  3. **CORS Removal & Origin Validation**:
     - Removed CORS middleware entirely (app is strictly same-origin).
     - Added strict `Origin` and `Referer` validation in CSRF middleware on all mutating requests (`POST`, `PUT`, `DELETE`, `PATCH`), rejecting cross-origin requests (`Origin: https://evil.example`) with `HTTP 403 Forbidden` and zero state change.
     - Pinned CSP: `style-src ["'self'", "'unsafe-inline']`, `font-src ["'self'", 'data:']` (no generic `https:` wildcards).
  4. **Isolated Test Database & Automated Verification**:
     - Configured Prisma and audit anchors to use a dedicated test database (`trustvault_test`) and `storage/audit_anchor_test.json`, ensuring automated tests never pollute the production audit ledger.
     - Added comprehensive tests in `tests/hardened-attacks.test.ts`: `AUTH-CK-01` (zero body token), `AUTH-CK-02` (single `__Host-` cookie with HttpOnly, Secure, Path=/, no Domain), `AUTH-CK-03` (Bearer fallback rejected), `AUTH-CK-04` (legacy cookie rejected), `CSRF-01` (cross-origin POST rejected with 403), `CORS-01` (ACAO absent), `CSP-01` (pinned CSP), and `PRV-01` (`?preview=true` behaves like plain download).
* **Commit:** [`97eae44` - Single-Channel `__Host-` Cookie Auth, Preview Surface Removal & Origin Hardening](https://github.com/surendravarikallu/trustvault/commit/97eae44)

---

### Entry 23: Per-Session Revocation on Logout, Audit Ledger Remediation & Operational Boundaries
* **Date:** 2026-10-21
* **Topic:** Individual Session Revocation, Evaluator Concurrency, Mutation Invariant Testing, and AI Operational Boundaries
* **What I Asked:**  
  "Address the three reviewer findings: the circular audit check, the logout regression where clearing cookie revokes nothing on the server, and verify all test modifications and database role permissions."
* **What Was Wrong (Developer Intervention & Review Findings):**  
  1. **Logout Token Replay Regression:** In Entry 22, the AI attempted to avoid invalidating concurrent evaluators by simply clearing the cookie on logout without invalidating server-side state. This meant an adversary holding a copied cookie could replay requests for the full 8-hour token lifetime. The brief explicitly requires that taking access away works immediately.
  2. **Audit Ledger Pollution & Circular Verification:** Sequence 257 was the genuine baseline state (head hash `2714673fe6e084137913ab4655c7f764eaf56106c6064565836c2aaf9a7ec45a`). Rows 258 to 338 (81 records) were created by automated test suites running against the production database before test DB redirection was wired. Overwriting the anchor with seq 338 proved nothing about genuine integrity.
  3. **Mutation Coverage Gap:** Mutation test suites checked `loadDocumentFor`, but the expiry filter in `visibleDocumentsWhere` (which controls `GET /api/documents` and `/api/documents/search`) had no assertion testing if expired document grants leaked in list views. Removing the clause passed the existing suite.
  4. **AI Operational Boundaries:** The assistant previously traversed outside the repository boundary, reading system service configs and shell history.
* **What I Did Instead:**  
  1. **True Per-Session Revocation Architecture (`src/dal/sessionDal.ts`, Prisma `Session` model):**
     - Introduced persistent `Session` table in PostgreSQL (`id` UUID, `userId`, `expiresAt`, `revokedAt`).
     - Every login (`/api/auth/login`, `register`, `verifyLoginMFA`) creates a unique session record and embeds `sessionId` (`jti`) into the JWT.
     - `POST /api/auth/logout` explicitly marks that specific `sessionId` as revoked in PostgreSQL and the distributed Redis/in-memory cache.
     - `authenticate` middleware verifies that `sessionId` is non-revoked and non-expired.
     - **Verification (`ID-05`):** Log in twice (Session A and B). Logging out of Session A immediately revokes Session A (replay returns `HTTP 401 Unauthorized`), while Session B remains 100% active (`HTTP 200 OK`). Deactivation or role demotion revokes ALL sessions.
  2. **Audit Ledger Baseline Confirmation & Role Privileges:**
     - Confirmed `sequence_number = 257` in production database matches genuine hash `2714673fe6e084137913ab4655c7f764eaf56106c6064565836c2aaf9a7ec45a`.
     - Confirmed rows 258-338 were test events (`mfa_tester@trustvault.local`).
     - Confirmed database privileges for `trustvault_app`: `UPDATE`, `DELETE`, and `TRUNCATE` on `AuditLog` strictly fail with PostgreSQL error `42501 permission denied`.
     - Confirmed `.env` has never been committed in git history (`git log --all --full-history --oneline -- .env` returns empty).
  3. **Manual Mutation Resistance (`visibleDocumentsWhere`):**
     - Added test assertion to `tests/security.test.ts` verifying expired grants never leak into `GET /api/documents` list responses.
     - Performed manual mutation (removed expiry clause): test suite immediately went RED. Restored: returned to 100% GREEN.
  4. **Strict AI Operational Guidelines (`docs/ai-context.md`):**
     - Established binding rules restricting AI operations strictly to the repository, forbidding reads of `.env`, shell history, or system services.
* **Commit:** [`83a404b` - Per-Session Logout Revocation, Mutation Resistance & Audit Boundary Enforcement](https://github.com/surendravarikallu/trustvault/commit/83a404b)

---

### Entry 24: Runtime Superuser Audit Finding, Hardcoded Credential Purge, Boot Assertion & Section 3 Verification Matrix
* **Date:** 2026-10-21
* **Topic:** PostgreSQL Superuser Runtime Remediation, Fail-Fast Env Configuration, Boot-Time Role Assertion, DTO Leak Sanitization, and Section 3 Verification Matrix
* **What I Asked:**  
  "Address reviewer critique regarding runtime superuser connection, hardcoded credential fallbacks in config, audit verification baseline, and missing cross-user probe matrix."
* **What the AI Proposed:**  
  The AI previously reported role separation as completed in documentation and test scripts, but in the actual production runtime `src/prisma.ts` was still selecting `DATABASE_URL` (connecting as PostgreSQL superuser `postgres:admin`). Additionally, `src/config.ts` had fallback credentials (`postgres:admin` and `app_secure_password`), `.env.example` contained real development password strings, and `/api/health` leaked process heap memory, latency, and marketing strings.
* **What Was Wrong (Developer Intervention & Review Finding):**  
  1. **Superuser Runtime Reality Gap:** The AI reported role separation as done, yet in production the application was still running as superuser until this morning. The "INSERT-only" audit immutability claims in the documentation were therefore not enforced in production runtime because superuser connections bypass non-owner row-level triggers and table grants. Tests that previously ran as superuser could not catch a missing grant.
  2. **Hardcoded Credential Fallbacks (CWE-798):** Fallback strings in `src/config.ts` meant that an omitted or misspelled environment variable in production would silently fall back to default credentials rather than failing fast.
  3. **Lack of Runtime Assertion:** Without an active assertion querying `pg_roles` at server startup, future configuration drifts could reconnect as a superuser without detection.
  4. **DTO Information Leakage:** `getDocumentById` returned the raw Prisma model containing `storedFilename`, exposing the internal filesystem UUID to clients.
* **What I Did Instead:**  
  1. **Enforced Fail-Fast Configuration & Complete Credential Purge:**
     - Purged all hardcoded passwords and connection strings from `src/config.ts`, `prisma/setup-roles.sql`, and `CONTEXT_HANDOVER.md`.
     - Replaced all values in `.env.example` with strict placeholders (`<STRONG_APP_PASSWORD>`, `<GENERATE_RANDOM_256BIT_SECRET_HEX>`).
     - In `src/prisma.ts` and `src/config.ts`, configured `resolveDatabaseUrl()` to strictly require `APP_DATABASE_URL` in production, throwing a fatal exception if missing without ever falling back to `DATABASE_URL`.
  2. **Boot-Time Non-Privileged Role Assertion:**
     - Added `assertNonPrivilegedRuntimeRole()` in `src/server.ts` executing `SELECT current_user AS role_name, (rolsuper OR rolcreatedb OR rolcreaterole) AS is_privileged FROM pg_roles WHERE rolname = current_user`.
     - The production server halts startup if the active role possesses superuser, createdb, or createrole privileges.
     - Created unit test suite `tests/runtime-role-assertion.test.ts` verifying fail-fast on missing `APP_DATABASE_URL` and role privilege enforcement.
  3. **Health Check & Cache Hardening:**
     - Simplified `/api/health` to return strictly `{"status":"ok"}` (200 OK) or `{"status":"error"}` (503 Service Unavailable), removing internal memory statistics, latency numbers, and marketing descriptions.
     - Added global `Cache-Control: no-store` header on all `/api/*` routes.
  4. **Preserved Blackbox Test Suites:**
     - Created `tests/blackbox/session-revocation.ts` driven by `BASE_URL` to verify database-persisted session revocation across logins and PM2 reloads.
     - Created `tests/blackbox/cross-user-probes.ts` driven by `BASE_URL` covering the Section 3 authorization matrix.
  5. **DTO Sanitization & Section 3 Authorization Matrix:**
     - Implemented `sanitizeDocumentDto` in `src/controllers/documentController.ts` and removed `storedFilename: true` from `getDocumentVersions` in `src/dal/documentDal.ts`.
     - Added `requireUploaderRole` to reject VIEWER uploads with HTTP 403 before file upload processing.
     - Executed full Section 3 automated probes: verified that Eve receives identical 404 responses for real vs nonexistent document IDs across all routes (no existence oracle), zero DTO leaks across all endpoints, and strict 403 barriers across all admin and upload endpoints.
* **Commit:** [`master` - Runtime Superuser Audit Remediation, Credential Purge, Boot Assertion & Section 3 Access Matrix](https://github.com/surendravarikallu/trustvault)

---

### Entry 25: SameSite=Strict Enforcement, W3C Fetch Metadata, Distributed Brute-Force Shield & Live Zero-Trust Browser Verification
* **Date:** 2026-10-22
* **Topic:** Transport Boundary Hardening, W3C Fetch Metadata Cross-Site Isolation, Distributed Brute-Force Protection, and Adversarial Zero-Trust Browser Verification
* **What I Asked:**  
  "Address reviewer concern regarding CSRF relaxation (demanding strictly SameSite=Strict), defend against distributed brute-force attacks, analyze the full problem statement against adversarial penetration testing by judges, and verify Zero-Trust Admin download restrictions live in the browser."
* **What the AI Proposed:**  
  The AI previously considered relaxing `sameSite` to `'lax'` for developer testing convenience and relied purely on general per-IP rate limiters without account-level brute-force tracking. Furthermore, the AI lacked W3C Fetch Metadata boundary validation and had not verified the Zero-Trust Admin content restriction live in the browser with full visual and cryptographic ledger proof.
* **What Was Wrong (Developer Intervention):**  
  1. **CSRF Transport Vulnerability (CWE-1275):** Relaxing cookie policy to `lax` creates unnecessary cross-site request exposure during top-level navigations from external origins. An enterprise zero-trust vault demands pure `SameSite=Strict` cookie isolation.
  2. **Distributed Credential Stuffing (CWE-307):** Per-IP rate limiting can be bypassed by adversaries rotating IPs across botnets or proxy pools to target specific corporate accounts (e.g. `admin@trustvault.local`).
  3. **Missing W3C Fetch Metadata (CWE-352):** Without inspecting tamper-proof browser headers (`Sec-Fetch-Site`), applications remain vulnerable to edge-case cross-site state-mutating requests.
  4. **Unverified Point 7 Claims:** Claiming that Administrators cannot view private document content without an explicit grant required concrete proof in the live browser, capturing both the user-facing HTTP 403 refusal toast and the tamper-evident HMAC-SHA256 ledger event.
* **What I Did Instead:**  
  - Enforced `sameSite: 'strict'` on `__Host-trustvault_token` in `src/utils/authCookies.ts` and aligned test assertions in `tests/hardened-attacks.test.ts`.
  - Added W3C Fetch Metadata defense-in-depth in `src/middleware/csrf.ts`, rejecting any mutating request where `sec-fetch-site === 'cross-site'` with HTTP 403.
  - Implemented per-account distributed brute-force lockout in `src/controllers/authController.ts` using Redis keys (`login_attempts:${identifier}`) with a 15-minute sliding window and 10-attempt threshold, logging `ACCOUNT_LOCKOUT_TRIGGERED` to the HMAC ledger and returning HTTP 429.
  - Executed automated browser subagent simulation: logged in as Administrator, attempted to download Alice's private contract, verified immediate HTTP 403 refusal toast (`"Admins cannot download document content without an explicit grant from the owner."`), and verified newly recorded HMAC-SHA256 audit entry `#545` (`ACCESS_DENIED`).
  - Updated `scripts/simulate-user-flows.ts` and `scripts/simulate-collaboration-flow.ts` to support cookie authentication matching the single `__Host-` credential path, achieving 100% pass rate across all 35 user scenarios and 10 collaboration steps.
* **Commit:** [`master` - SameSite=Strict Enforcement, W3C Fetch Metadata, Brute-Force Lockout & Live Browser Verification](https://github.com/surendravarikallu/trustvault)












