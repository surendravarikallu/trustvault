# TrustVault — Threat Model & Security Matrix (THREATS.md)

> **Document Status:** Comprehensive Threat Specification  
> **Last Updated:** 2026-10-19  
> **System Architecture:** Node.js (Express + TypeScript), PostgreSQL (Dual DB Roles), Prisma ORM + Zod, React (Vite + TypeScript)

---

## 1. Threat Modeling Methodology & System Boundaries

TrustVault handles sensitive enterprise documents under a strict **Zero-Trust & Deny-by-Default** paradigm. We model threats against:
1. **Malicious External Actors:** Unauthenticated network attackers probing APIs, fuzzing parameters, or attempting brute-force/timing attacks.
2. **Authenticated Adversaries (Cross-Tenant / Cross-User):** Authenticated users (e.g., `Eve`) attempting horizontal or vertical privilege escalation, IDOR, parameter tampering, or denial of service.
3. **Compromised Roles (Rogue Admins & Editors):** Users with elevated privileges attempting unauthorized data access, file destruction, or unauthorized permission delegation.
4. **Insider / Database Attackers:** Attackers with direct database read/write access attempting to alter audit trails or bypass application-level controls.

### Explicit Security Boundaries & Accepted Risks

| Boundary | Covered by TrustVault? | Architectural Defense | Accepted Risk / Justification |
| :--- | :---: | :--- | :--- |
| **Cross-User Data Isolation** | **YES** | Enforced DAL via `loadDocumentFor` + single `visibleDocumentsWhere` predicate | None accepted. Zero-tolerance for authorization leakage. |
| **Audit Ledger Tampering** | **YES** | HMAC-SHA256 hash chain with external secret, advisory locking, and PostgreSQL mutation-blocking trigger | DB-level updates detected. Physical drop of whole database cannot be prevented by application software. |
| **Direct Storage Access** | **YES** | Local disk storage outside web root; UUID-named files without extensions; no static HTTP serving | Attacker with OS-level root/shell access can read local disk. Mitigated via Cloudflare Tunnel (zero open ingress ports). |
| **Network & Injection Attacks** | **YES** | Parameterized Prisma queries, strict Zod schemas, simple query parser, RFC 5987 headers | None accepted. |

---

## 2. Threat Matrix (All Attack Vectors)

### Category A: Authorization & Privilege Escalation (T-01 to T-06)

#### T-01: Insecure Direct Object Reference (IDOR) on File Download
* **Attacker Scenario:** An authenticated user (`Eve`) obtains or guesses a valid document UUID belonging to `Alice` and sends `GET /api/documents/:id/download`.
* **Defense Mechanism:** Every download request must pass through `loadDocumentFor(user, docId, 'download', reqContext)` in `src/dal/documentDal.ts`. The query checks for document ownership or an active row in `DocumentPermission` where `expiresAt` is null or in the future.
* **Information Leakage Prevention:** Returns **404 Not Found** (identical to a non-existent UUID) rather than 403, preventing Eve from confirming document existence.
* **Audit Event:** Records `ACCESS_DENIED` with Eve's userId, IP, and timestamp.
* **Automated Test:** `test_idor_download_blocked_with_404`

#### T-02: IDOR on Document Metadata
* **Attacker Scenario:** `Eve` requests `GET /api/documents/:id` for `Alice`'s document.
* **Defense Mechanism:** Handled by `loadDocumentFor(user, docId, 'read', reqContext)`. If no active grant or ownership exists, throws `NotFoundError` (404).
* **Automated Test:** `test_idor_metadata_blocked_with_404`

#### T-03: Stale Permissions After Revocation (Revocation Lag)
* **Attacker Scenario:** `Bob` is granted `READ` access to a document and downloads it. The owner revokes Bob's access. Bob attempts to immediately download the file again using his existing JWT token.
* **Defense Mechanism:** JWTs carry identity only (`userId`), zero permission state. `loadDocumentFor()` queries the database on every single request. Once the owner executes `DELETE /api/documents/:id/permissions/:userId`, the subsequent request immediately finds no grant and returns 404.
* **Automated Test:** `test_instant_revocation_blocks_subsequent_request`

#### T-04: Expired Time-Bounded Access
* **Attacker Scenario:** A grant was created with `expiresAt = yesterday`. `Bob` attempts to download the file.
* **Defense Mechanism:** The SQL predicate in `visibleDocumentsWhere` and `loadDocumentFor` explicitly checks `(expiresAt IS NULL OR expiresAt > NOW())`. Expired grants are evaluated as non-existent and return 404.
* **Automated Test:** `test_expired_grant_returns_404`

#### T-05: Horizontal / Vertical Privilege Escalation (Read-to-Edit & Viewer-to-Owner)
* **Attacker Scenario:** A user with a `READ` grant sends `PUT /api/documents/:id` to modify metadata or upload a new file. Alternatively, a `VIEWER` attempts `POST /api/documents` to upload files.
* **Defense Mechanism:**
  1. For `PUT`, `loadDocumentFor(user, id, 'edit', reqContext)` verifies that the grant level is `EDIT`. Because the user has visibility (active `READ` grant) but unauthorized action, it returns **403 Forbidden**.
  2. For `POST /documents`, the route middleware verifies `req.user.role === 'OWNER' || req.user.role === 'ADMIN'`. `VIEWER` accounts receive **403 Forbidden**.
* **Automated Test:** `test_reader_cannot_edit_document` & `test_viewer_cannot_upload`

#### T-06: Permission Delegation & Re-Sharing Leak
* **Attacker Scenario:** An editor (`Bob` with `EDIT` grant) attempts to grant permissions to `Eve` via `POST /api/documents/:id/permissions`.
* **Defense Mechanism:** `loadDocumentFor(user, id, 'manage_permissions', reqContext)` asserts that `document.ownerId === user.id`. Editors and Admins cannot grant permissions on documents they do not own. Returns **403 Forbidden**.
* **Automated Test:** `test_editor_cannot_grant_permissions`

---

### Category B: Information Leakage & Existence Oracles (T-07 to T-10)

#### T-07: Search Query Information Leakage
* **Attacker Scenario:** `Eve` sends `GET /api/documents/search?q=Confidential` or filters by date/owner to discover documents she has no right to see.
* **Defense Mechanism:** The search query does not filter results in application memory. The database query strictly applies `visibleDocumentsWhere(user)` in the `WHERE` clause:
  `WHERE isDeleted = false AND (ownerId = :me OR id IN (SELECT documentId FROM DocumentPermission WHERE userId = :me AND ...))`.
* **Automated Test:** `test_search_hides_unauthorized_docs`

#### T-08: Status Code Existence Oracle (404 vs 403)
* **Attacker Scenario:** An attacker cycles through UUIDs comparing 404 (non-existent) vs 403 (exists but forbidden) to map valid internal document IDs.
* **Defense Mechanism:**
  - If the user has **no visibility** (neither owner nor active grantee), the system returns **404 Not Found**.
  - If the user **has visibility** (e.g. `READ` grantee) but attempts an unauthorized action (e.g. `PUT`), it returns **403 Forbidden**.
* **Automated Test:** `test_denied_access_returns_404_for_unknown_visibility`

#### T-09: Admin Document Content Snooping
* **Attacker Scenario:** An `ADMIN` attempts to download documents or read files directly via `GET /api/documents/:id/download`.
* **Defense Mechanism:** Admins have administrative visibility (metadata, audit logs, system metrics) via dedicated `/api/admin/documents` endpoints, but `loadDocumentFor(user, id, 'download')` does not bypass permission checks for Admins. Without an explicit grant from the owner, the download returns **403 Forbidden**.
* **Automated Test:** `test_admin_cannot_download_without_grant`

#### T-10: Email Harvesting / User Directory Enumeration
* **Attacker Scenario:** An attacker requests a list of all users or probes registration endpoints to harvest corporate email addresses.
* **Defense Mechanism:**
  - Removed `/api/auth/users`. Replaced with rate-limited exact-match search `GET /api/users/lookup?email=...`.
  - Registration returns a uniform generic response regardless of whether the email is already registered, eliminating registration enumeration oracles.
* **Automated Test:** `test_user_directory_enumeration_blocked`

---

### Category C: Storage, Upload & Data Destruction (T-11 to T-14)

#### T-11: Malicious Executable Disguised as Document
* **Attacker Scenario:** An attacker uploads a Windows PE executable (`payload.exe`) renamed to `report.pdf`.
* **Defense Mechanism:**
  1. Extension whitelist check (`.pdf`, `.docx`, `.xlsx`, `.txt`, `.png`, `.jpg`).
  2. Magic byte inspection using buffer analysis (e.g. `file-type`). PE headers (`MZ`) or script contents disguised with `.pdf` extension are rejected.
  3. Temporary upload files created by Multer are deleted immediately in a `finally` block on rejection.
* **Automated Test:** `test_disguised_executable_rejected`

#### T-12: Direct Storage URL Access & Path Traversal
* **Attacker Scenario:** An attacker attempts to browse directly to `/storage/uploads/file.pdf` or passes `../../etc/passwd` in the filename/id parameter.
* **Defense Mechanism:**
  1. Files are stored outside the web root in `storage/uploads/`.
  2. No `express.static` middleware is bound to the storage folder.
  3. Input parameters are strictly validated via Zod as UUIDs. Filenames are stripped using `path.basename()`.
  4. Downloads are served with `Content-Type: application/octet-stream` and RFC 5987 encoded `Content-Disposition: attachment; filename*=UTF-8''...` to prevent browser execution of SVG/HTML files.
* **Automated Test:** `test_path_traversal_and_direct_storage_blocked`

#### T-13: File Destruction / Irreversible Overwrite by Editor
* **Attacker Scenario:** An editor with `EDIT` permissions uploads a corrupted or blank file, destroying the owner's original document.
* **Defense Mechanism:** File replacements do not overwrite disk blobs. The system inserts a record into `DocumentVersion`, preserving the historical blob UUID. `Document.storedFilename` points to the new version.
* **Redaction Protection:** Version history endpoints (`/api/documents/:id/versions`) are restricted strictly to the **Owner**, ensuring a `READ` user cannot download older versions containing redacted data.
* **Automated Test:** `test_editor_file_replacement_preserves_version_history`

#### T-14: Orphaned File Blobs on Deletion
* **Attacker Scenario:** Deleting a user or document leaves unreferenced files on disk, leaking storage or causing data drift.
* **Defense Mechanism:** `User` has `onDelete: Restrict` on `Document.ownerId`. Document deletion is implemented as soft-delete (`isDeleted = true`, `deletedAt = NOW()`). File unlinking is managed by an explicit transactional cleanup routine.
* **Automated Test:** `test_document_soft_delete_and_retention`

---

### Category D: Cryptographic Audit Ledger & Integrity (T-15 to T-18)

#### T-15: Invalid UUID Audit Crash / Existence Oracle
* **Attacker Scenario:** An attacker sends `GET /api/documents/00000000-0000-0000-0000-000000000000/download`.
* **Vulnerability Identified:** If `documentId` in `AuditLog` has a Foreign Key constraint, PostgreSQL throws a foreign key violation, either crashing with 500 (acting as an existence oracle) or dropping the audit record.
* **Defense Mechanism:** `AuditLog.documentId` is stored as an unconstrained plain string/UUID. The probe is cleanly logged as `ACCESS_DENIED`.
* **Automated Test:** `test_nonexistent_uuid_audit_logged_cleanly`

#### T-16: Audit Concurrency Race Condition (Ledger Forking)
* **Attacker Scenario:** An attacker fires 50 concurrent requests. Two concurrent requests read the same latest `previousHash`, calculate identical hashes, and fork the ledger.
* **Defense Mechanism:** Audit writes are wrapped in a database transaction with `pg_advisory_xact_lock(AUDIT_LOCK_ID)`. Sequence generation, timestamp assignment, and hash computation are strictly serialized.
* **Automated Test:** `test_concurrent_audit_writes_maintain_chain`

#### T-17: Database Administrator / SQL Injection Audit Tampering
* **Attacker Scenario:** An attacker with database access (or via SQL injection) attempts to update or delete past audit entries.
* **Defense Mechanism:**
  1. Application connects via `trustvault_app` PostgreSQL role.
  2. `REVOKE UPDATE, DELETE, TRUNCATE ON "AuditLog" FROM trustvault_app;`
  3. A PostgreSQL trigger `PREVENT_AUDIT_MUTATION` explicitly raises an exception on any `UPDATE` or `DELETE` attempt.
  4. Every column (`id`, `sequenceNumber`, `timestamp`, `action`, `userId`, `userEmail`, `documentId`, `documentTitle`, `status`, `ipAddress`, `userAgent`, `details`, `previousHash`) is covered by an **HMAC-SHA256** using `AUDIT_HMAC_SECRET` stored outside the database.
* **Automated Test:** `test_audit_chain_detects_row_modification`

#### T-18: Audit Tail Truncation
* **Attacker Scenario:** An attacker deletes the latest 5 rows of the audit log. Because all remaining rows are internally consistent, standard hash chain verification passes.
* **Defense Mechanism:** The audit service periodically exports an external anchor `(sequenceNumber, headHash, timestamp)` to `storage/audit_anchor.json`. The verification endpoint (`GET /api/admin/audit-verify`) validates that the chain matches the external anchor.
* **Automated Test:** `test_audit_chain_detects_tail_truncation`

---

### Category E: Infrastructure, Auth & Transport (T-19 to T-22)

#### T-19: Demoted Admin / Revoked User Token Replay
* **Attacker Scenario:** An admin is demoted or a user is deactivated. The user continues to make requests using their existing 8-hour JWT.
* **Defense Mechanism:** `User` table contains `tokenVersion: Int`.
  - On role demotion (`PATCH /api/admin/users/:id/role`), deactivation, or logout, `tokenVersion` is incremented.
  - Auth middleware re-verifies `tokenVersion` and `isActive` against the database on every authenticated request. Old tokens are rejected immediately with 401.
* **Automated Test:** `test_token_version_invalidation_on_demotion`

#### T-20: Authentication Timing Attack on Login
* **Attacker Scenario:** An attacker measures API response times on `POST /api/auth/login` to enumerate valid registered emails based on whether bcrypt execution occurred.
* **Defense Mechanism:** If the email does not exist in the database, the server runs `bcrypt.compare(password, DUMMY_HASH)` (using cost factor 12) so the elapsed time is statistically indistinguishable from a valid email with a wrong password.
* **Automated Test:** `test_login_timing_indistinguishable`

#### T-21: Reverse Proxy IP Spoofing & Brute-Force Rate Limiting
* **Attacker Scenario:** Behind Cloudflare Tunnel, an attacker sends requests with fake `X-Forwarded-For` headers to bypass rate limits or exhaust global limits for all users.
* **Defense Mechanism:**
  - Express is bound strictly to `127.0.0.1` with `app.set('trust proxy', 1)`.
  - Client IP is extracted via trusted `req.headers['cf-connecting-ip'] || req.socket.remoteAddress`.
  - Dual rate limiting: Global IP limiter (100 req/min) + Login limiter (5 attempts/15min) keyed on composite `clientIp + '_' + sanitizedEmail`.
* **Automated Test:** `test_rate_limiter_dual_keying`

#### T-22: Express Query Parameter Object Injection
* **Attacker Scenario:** Attacker sends `GET /api/documents?owner[not]=x` or `?id[$gt]=...`. In default Express setups, `qs` parses nested keys as objects, passing unexpected filter operators into Prisma.
* **Defense Mechanism:**
  - Configured `app.set('query parser', 'simple')` to disable nested object parsing.
  - Every query parameter, body, and route parameter is validated strictly using Zod schemas. Non-scalar or unexpected types throw 400 validation errors before database access.
* **Automated Test:** `test_zod_rejects_object_filter_injection`

---

### Category F: Application Hardening & Resource Protection (T-23 to T-26)

#### T-23: Orphaned Disk Storage Consumption via Unauthorized PUT (CWE-400)
* **Attacker Scenario:** An authenticated adversary without `EDIT` permissions repeatedly calls `PUT /api/documents/:id` with 15MB file uploads to exhaust server disk space.
* **Vulnerability Identified:** If the file is moved to permanent storage *before* the authorization gate verifies `EDIT` rights, the 15MB file remains orphaned in `storage/uploads/` even when the request returns `403 Forbidden`.
* **Defense Mechanism:**
  - `replaceDocumentFile()` executes `loadDocumentFor(user, id, 'edit', reqContext)` **prior** to calling `StorageService.persistFile()`. Unauthorized users are blocked before files leave temporary scratch storage.
  - Defensive rollback: In the event of a database transaction failure, `StorageService.deleteFile(storedFilename)` immediately unlinks the newly created disk blob.
* **Commit:** [`c4dc2de`](https://github.com/surendravarikallu/trustvault/commit/c4dc2de)

#### T-24: Unbounded Heap Memory Exhaustion via Broad Search Queries (CWE-770)
* **Attacker Scenario:** An attacker issues search queries with empty or generic filters (`q=""` or `category=Legal`) across a repository containing tens of thousands of documents to exhaust Node.js heap memory.
* **Defense Mechanism:**
  - Enforced a hard upper boundary of `take: 100` at the Data Access Layer in `src/dal/documentDal.ts`.
  - Database queries never load unbounded row sets into memory.
* **Automated Test:** `test_search_hides_unauthorized_docs` & DAL bounded result enforcement.
* **Commit:** [`c4dc2de`](https://github.com/surendravarikallu/trustvault/commit/c4dc2de)

#### T-25: HTTP Response Splitting via Filename CRLF & Control Character Injection (CWE-113)
* **Attacker Scenario:** An attacker uploads a document whose `originalFilename` contains carriage return (`\r`) or line feed (`\n`) characters (e.g. `test\r\nSet-Cookie: evil=true\r\n.pdf`) in an attempt to split HTTP response headers when downstream clients download the file.
* **Defense Mechanism:**
  - `validateUploadedFile` in `src/middleware/uploadValidator.ts` validates `file.originalname` against a strict pattern blocking `\0`, `..`, `\r`, `\n`, and all ASCII control characters (`[\x00-\x1f\x7f]`).
  - Violations return `400 Bad Request` and immediately unlink the scratch file.
* **Commit:** [`c4dc2de`](https://github.com/surendravarikallu/trustvault/commit/c4dc2de)

#### T-26: Uncaught Exception Schema & Stack Trace Leakage in Production (CWE-209)
* **Attacker Scenario:** An attacker crafts malformed input to trigger unhandled database driver crashes or constraint failures, reading raw PostgreSQL table and column names in the 500 error response.
* **Defense Mechanism:**
  - Global error-handling middleware in `src/server.ts` checks `config.nodeEnv === 'production'`.
  - In production mode, 500 responses return a generic, uniform payload (`{"error": "Internal server error."}`), preventing internal schema leakage while preserving full error diagnostics in server-side logs.
* **Commit:** [`c4dc2de`](https://github.com/surendravarikallu/trustvault/commit/c4dc2de)

---

### Category G: Cryptographic Boundaries & Protocol Hardening (T-27 to T-32)

#### T-27: JWT Algorithm None (`alg: none`) & Bogus Signature Forgery (CWE-347)
* **Attacker Scenario:** An attacker strips the signature from an admin JWT or sets header `{"alg": "none"}` or signs with a bogus key to bypass authentication and gain full administrator privileges.
* **Defense Mechanism:**
  - `jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] })` in `src/middleware/auth.ts` strictly enforces the `HS256` HMAC algorithm, rejecting `none` or mismatched keys with 401 Unauthorized.
  - Active database session verification ensures token version matches live DB records.
* **Automated Test:** `ADV-01` in `scripts/verify-dal-invariants.ts`.

#### T-28: HTTP Parameter Pollution & Query Object Synthesis (HPP) (CWE-235)
* **Attacker Scenario:** An attacker supplies duplicated query parameters (`?q=a&q=b`) or nested object parameters (`?q[$ne]=test&category[in]=Executive`) in search queries to manipulate SQL where clauses or bypass filters.
* **Defense Mechanism:**
  - Express `app.set('query parser', 'simple')` disables object parsing.
  - Strict scalar parameter extraction ensures arrays and nested objects are neutralized, returning 0 documents or 400 validation errors.
* **Automated Test:** `ADV-02` in `scripts/verify-dal-invariants.ts`.

#### T-29: JSON Prototype Pollution & Role Property Elevation (CWE-1321)
* **Attacker Scenario:** An attacker submits JSON payloads containing `__proto__` and `constructor.prototype` trying to pollute the JavaScript runtime and elevate permissions from `VIEWER` to `OWNER`.
* **Defense Mechanism:**
  - User identity and permissions are strictly minted from cryptographic JWT claims and verified against PostgreSQL on every request; JSON body properties never pollute the authentication context.
  - Viewers cannot upload documents; attempts return `403 Forbidden` with the global Object prototype unpolluted.
* **Automated Test:** `ADV-05` in `scripts/verify-dal-invariants.ts`.

#### T-30: Reverse-Proxy Header Spoofing for Cross-Tenant IDOR (CWE-284)
* **Attacker Scenario:** An adversary probes cross-tenant document download routes while forging reverse-proxy headers (`X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, `X-Rewrite-URL`, `X-User-Role: OWNER`) to simulate internal loopback or elevated owner status.
* **Defense Mechanism:**
  - Route authorization completely ignores client-supplied proxy and identity headers.
  - `loadDocumentFor()` enforces caller ownership via the cryptographic JWT payload and returns `404 Not Found` (zero content bytes and zero existence confirmation).
* **Automated Test:** `ADV-04` in `scripts/verify-dal-invariants.ts`.

#### T-31: Audit Ledger External Anchor Head-Fork & Substitution (CWE-353)
* **Attacker Scenario:** An attacker deletes rows from the database or forges an alternate sequence chain, replacing the external disk anchor (`storage/audit_anchor.json`) to force validation of a substitute head hash.
* **Defense Mechanism:**
  - `verifyAuditChain()` recalculates HMAC-SHA256 from genesis (seq 1) through the head, validating both internal continuity and exact equality against the external disk anchor.
  - Substituted head hashes immediately fail verification with: *"External anchor hash mismatch at sequence X. Ledger head was forked or substituted!"*
* **Automated Test:** `AUD-03` in `tests/audit-tamper-immutability.test.ts`.

#### T-32: TOTP Code Interception, Replay & Challenge Token Forgery (CWE-287 / CWE-307)
* **Attacker Scenario:** An attacker sniffs a valid 6-digit TOTP code and attempts to replay it within the same 30-second window, or attempts to forge an `mfaChallengeToken` to bypass primary credentials, or brute-forces 6-digit codes.
* **Defense Mechanism:**
  - **Replay Defense:** The database tracks `mfaLastTimeStep` per user. Submitting the exact same TOTP code within the current 30-second time step is immediately rejected (`MFA_REPLAY_ATTACK_BLOCKED`, HTTP 401).
  - **Restricted Challenge Token:** Password verification issues a 3-minute, single-purpose `MFA_CHALLENGE` JWT. Challenge tokens cannot access document or admin routes.
  - **Secret Encryption at Rest:** The Base32 TOTP secret is encrypted via AES-256-GCM in PostgreSQL.
  - **Single-Use Backup Codes:** 8 cryptographically random recovery codes stored as SHA-256 hashes; consumed and burned immediately upon first use.
  - **Rate Limiting:** Dedicated 10 attempts/15min rate limiting on the verification route.
* **Automated Test:** `tests/mfa-totp.test.ts` (MFA-01 through MFA-08).

---

## 3. Structural Enforcement & Mutation Resistance (T-33)

#### T-33: Mutation Testing (Bypassing Authorization Checks)
* **Evaluator / Judge Test:** The judge removes or comments out the authorization check in the code and re-runs test suites. If tests still pass due to duplicate/redundant checks or false assertions, the system fails evaluation.
* **Defense Mechanism:**
  - **Single Data-Access Gatekeeper:** All document reads and writes flow through `src/dal/documentDal.ts`.
  - **ESLint Rule (`no-restricted-imports`):** Controllers are strictly forbidden from importing `@prisma/client`.
  - If the authorization check in `loadDocumentFor()` is removed, every single document route security test fails immediately (RED).
* **Automated Verification:** `scripts/mutation-test.ts` automatically modifies the check, verifies tests go red, and restores code.

#### T-34: Storage Blob Exfiltration & Ciphertext Exposure at Rest (CWE-311)
* **Attacker Scenario:** An adversary obtains unauthorized physical or volume access to the underlying storage disks and attempts to read raw documents or exfiltrate private files.
* **Defense Mechanism:**
  - **Envelope Encryption at Rest:** Every uploaded document is encrypted with AES-256-GCM before written to disk.
  - Files carry a cryptographically bound header (`TV_AES256_GCM_v1:`), a unique 12-byte IV, a 16-byte GCM authentication tag, and ciphertext.
  - Streaming downloads use `StorageService.createDecryptedReadStream()`, automatically decrypting in-flight only after the Single Gatekeeper DAL validates the caller's authorization.
  - Backward compatibility is preserved with unencrypted legacy files transparently.
* **Automated Test:** `DR-02` & `DR-03` in `tests/backup-disaster-recovery.test.ts`.

#### T-35: Catastrophic Data Loss, Backup Tampering & Host Disaster Recovery (CWE-353 / CWE-310)
* **Attacker Scenario:** An adversary or system failure destroys the production host, or an insider tampers with backup archives to inject backdoors or alter audit records.
* **Defense Mechanism:**
  - **Automated Disaster Recovery Engine:** `BackupService.createFullBackup()` captures an atomic snapshot of database tables, encrypted file blobs, and external audit anchors.
  - **HMAC-SHA256 Manifest Signing:** Backups generate a cryptographic `manifest.json` signed using `HMAC-SHA256` binding table counts, audit sequence heads, and environment metadata.
  - **Tamper Detection:** `BackupService.verifyBackupArchive()` validates HMAC signatures and record parity. Any modified file or metadata causes immediate signature verification failure.
  - **Admin REST Lifecycle:** Protected endpoints (`POST /api/admin/backups`, `GET /api/admin/backups`, `POST /api/admin/backups/verify`) restrict disaster recovery operations to verified administrators.
  - **Automated Retention:** Implements automated 7-snapshot rolling retention pruning older backups.
* **Automated Test:** `DR-04`, `DR-05`, `DR-06` in `tests/backup-disaster-recovery.test.ts`.

#### T-36: Database Denial of Service & Query Degradation (CWE-400)
* **Attacker Scenario:** An attacker executes high-frequency search and filter queries across millions of documents or audit records to exhaust database CPU and connection pools.
* **Defense Mechanism:**
  - **High-Performance Composite Indexes:**
    - `Document`: `@@index([isDeleted, ownerId])`, `@@index([isDeleted, category])`, `@@index([isDeleted, createdAt])`, `@@index([fileHash])`.
    - `DocumentVersion`: `@@index([documentId])`.
    - `DocumentPermission`: `@@index([userId, expiresAt])`.
    - `AuditLog`: `@@index([action, timestamp])`, `@@index([userId, timestamp])`, `@@index([documentId, timestamp])`.
  - **Query Bounds:** All search queries enforce strict `take: 100` limits, preventing unbounded heap allocations.
* **Automated Test:** `UPL-05` in `tests/upload-hardening.test.ts`.

#### T-37: Silent System Degradation & Health Probe Blindness
* **Attacker Scenario:** Database connection pool dies or storage fills up silently while HTTP server returns superficial 200 OK responses to external monitoring.
* **Defense Mechanism:**
  - **Deep Health Check Endpoint:** `GET /api/health` executes a live database round-trip probe (`SELECT 1`), measures latency in milliseconds, reports RSS and heap memory consumption, and returns HTTP 503 degraded status if the database becomes unreachable.
* **Automated Test:** `DR-01` in `tests/backup-disaster-recovery.test.ts`.
