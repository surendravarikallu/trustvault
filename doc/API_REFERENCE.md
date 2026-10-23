# 🔌 TrustVault Enterprise API Reference Manual

**Base URL**: `https://trustvalt.me` (or `http://127.0.0.1:7777` in local environment)  
**Authentication Scheme**: Single-Channel `__Host-` Cookie (`Cookie: __Host-trustvault_token=<jwt>`)  
**Cookie Security**: `HttpOnly; Secure; SameSite=Strict; Path=/` (Zero JavaScript access, no `Domain` attribute)  
**Data Format**: `application/json` (Multipart for document uploads)  
**Security Standard**: Zero-Trust Single Gatekeeper DAL (`loadDocumentFor()`) on 100% of Document Endpoints  

---

## 1. System Telemetry & Health Probe

### 1.1 Minimal Health Check
`GET /api/health`

Performs an active database round-trip check (`SELECT 1`). Returns a strictly minimal status object without leaking internal heap memory, latency metrics, or marketing labels (Defense against CWE-200 reconnaissance).

#### Headers Enforced:
* `Cache-Control: no-store`
* `X-Content-Type-Options: nosniff`

#### Response (`HTTP 200 OK`):
```json
{
  "status": "ok"
}
```

---

## 2. Authentication & Identity Lifecycle (`/api/auth`)

### 2.1 Authenticate Principal (Login)
`POST /api/auth/login`

Validates user credentials against salted Bcrypt-12 hashes. Timing attacks are neutralized via dummy bcrypt comparisons on non-existent usernames.

* **Brute-Force Lockout (CWE-307 / Threat T-61)**: Redis-backed sliding window (`10 attempts / 15 minutes`). Breaching the threshold triggers `HTTP 429 Too Many Requests` and an `ACCOUNT_LOCKOUT_TRIGGERED` audit event.
* **Zero Body Token Exposure (Threat T-55)**: The response body contains `{ user }` only. The JWT is emitted strictly via the `Set-Cookie` header.

#### Request Body:
```json
{
  "usernameOrEmail": "owner@trustvault.local",
  "password": "Owner@TrustVault2026!"
}
```

#### Response (`HTTP 200 OK` - Standard Login):
```http
HTTP/1.1 200 OK
Set-Cookie: __Host-trustvault_token=eyJhbGciOi...; Path=/; HttpOnly; Secure; SameSite=Strict
Content-Type: application/json

{
  "user": {
    "id": "c1f7a8b2-3e4d-4c5b-8a7e-1a2b3c4d5e6f",
    "email": "owner@trustvault.local",
    "name": "Alice Document Owner",
    "role": "OWNER",
    "mfaEnabled": false
  }
}
```

#### Response (`HTTP 200 OK` - MFA Challenge State):
```json
{
  "mfaRequired": true,
  "mfaChallengeToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 2.2 Complete MFA Two-Factor Login
`POST /api/auth/mfa/verify-login`

Exchanges a 3-minute restricted `mfaChallengeToken` and a 6-digit TOTP code (or single-use emergency backup code) for an authenticated session. Replay defense rejects duplicate codes within the same 30-second window (CWE-287).

#### Request Body:
```json
{
  "mfaChallengeToken": "<token_from_login>",
  "code": "482910"
}
```

---

### 2.3 Terminate Session (Logout)
`POST /api/auth/logout`

Permanently revokes the caller's specific `sessionId` in the PostgreSQL `Session` table and distributed Redis cache. Clears the client cookie. Subsequent attempts to replay the token return `HTTP 401 Unauthorized`.

#### Response (`HTTP 200 OK`):
```json
{
  "message": "Logged out successfully."
}
```

---

### 2.4 Authenticated Identity Context
`GET /api/auth/me`

Validates session non-revocation in the database and returns the current principal profile.

---

## 3. Document Vault & Gatekeeper Endpoints (`/api/documents`)

All document endpoints are funneled through the **Single Gatekeeper DAL** (`loadDocumentFor()`).

### 3.1 Upload Encrypted Document
`POST /api/documents` (Requires `OWNER` or `ADMIN` role)

Accepts multipart file payloads. Multi-stage upload pipeline:
1. **Extension Whitelist**: Permits strictly `.pdf`, `.png`, `.jpg`, `.txt` (removes `.docx` and `.xlsx` to eliminate macro execution vectors).
2. **Buffer Magic Byte Verification**: Rejects disguised executables (Windows PE `MZ`, Linux ELF).
3. **Heuristic Threat Scanner**: Deeply parses PDF object streams, rejecting `/Launch`, `/JavaScript`, and obfuscated commands.
4. **Envelope Encryption at Rest**: Encrypts file using RFC 5869 HKDF-SHA256 derived keys and AES-256-GCM before writing to opaque UUID storage.

#### Form Data Parameters:
* `file`: Binary payload (Max: 25 MB).
* `title`: Document title (String).
* `category`: Classification (`Legal`, `Finance`, `HR`, `Engineering`, `Compliance`).
* `description`: Optional handling notes.

#### Response (`HTTP 201 Created`):
```json
{
  "message": "Document uploaded successfully.",
  "document": {
    "id": "8fa1e2b4-5c6d-4e7f-8a9b-0c1d2e3f4a5b",
    "title": "Master Services Agreement 2026",
    "category": "Legal",
    "originalFilename": "MSA_2026_Final.pdf",
    "fileSize": 412850,
    "fileHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "createdAt": "2026-10-22T14:15:00.000Z"
  }
}
```

---

### 3.2 List Vault Documents
`GET /api/documents?page=1&limit=20`

Returns documents scoped strictly by the shared `visibleDocumentsWhere(user)` predicate. Non-owners see only documents with active, unexpired clearance grants.

---

### 3.3 Search Documents
`GET /api/documents/search?q=query&owner=name&category=cat&fromDate=ISO&toDate=ISO`

Executes scoped full-text search bounded to `take: 100` to prevent heap memory exhaustion. Unshared documents are never returned.

---

### 3.4 Retrieve Document Metadata
`GET /api/documents/:id`

* If caller has active grant or ownership: Returns sanitized document metadata.
* **If caller has zero clearance: Returns `HTTP 404 Not Found` (CWE-209 Existence Oracle Defense).**

---

### 3.5 Secure Document Download
`GET /api/documents/:id/download`

Streams the in-memory decrypted file with `Content-Disposition: attachment; filename="..."` and `X-Content-Type-Options: nosniff`.

* **Admin Zero-Trust Barrier**: System Administrators attempting to download private documents without an explicit owner grant receive **`HTTP 403 Forbidden`** (`"Admins cannot download document content without an explicit grant from the owner."`).
* **Unshared Caller**: Receives **`HTTP 404 Not Found`** (Identical to nonexistent UUIDs).
* **Burn-on-Download Protocol**: If granted with `burnOnDownload: true`, the grant auto-revokes immediately upon socket stream completion (`res.on('finish')`). Subsequent attempts return `HTTP 404`.

---

### 3.6 Upload Revision / New Version
`PUT /api/documents/:id` (Requires `OWNER` or `EDIT` clearance)

Replaces the active binary payload. Archives the prior version into `DocumentVersion` with incremented `versionNumber` and SHA-256 digest, preserving forensic continuity.

---

### 3.7 Delegate Access Clearance
`POST /api/documents/:id/permissions` (Strictly Document Owner Only)

Grants access to a designated principal. Non-owners receive `HTTP 403 Forbidden`.

#### Request Body:
```json
{
  "targetEmail": "viewer@trustvault.local",
  "permissionLevel": "READ",
  "expiresAt": "2026-10-31T23:59:59.000Z",
  "burnOnDownload": false
}
```

---

### 3.8 Revoke Access Clearance
`DELETE /api/documents/:id/permissions/:userId` (Document Owner Only)

Instantly severs access. The very next download request from the revoked principal evaluates `activeGrant = null` and returns `HTTP 404 Not Found`.

---

## 4. Administrative & Governance Endpoints (`/api/admin`)

Requires `role === 'ADMIN'`.

### 4.1 Verify Cryptographic Audit Ledger
`GET /api/admin/audit-verify`

Traverses all records in `AuditLog` from sequence `#1` to current head. Recomputes HMAC-SHA256 digests over all 13 canonical columns and asserts parity against the external disk anchor (`storage/audit_anchor.json`).

#### Response (`HTTP 200 OK`):
```json
{
  "valid": true,
  "totalRecords": 545,
  "headSequence": "545",
  "headHash": "41d36b7a...",
  "anchorMatched": true
}
```

---

### 4.2 Query Immutable Audit Trail
`GET /api/admin/audit-logs?page=1&limit=50&action=ACCESS_DENIED`

Returns paginated forensic records enriched with resolved human user names and event story narratives.

---

### 4.3 Identity Provisioning & Governance
* `GET /api/admin/users`: List all enterprise identities.
* `POST /api/admin/users`: Provision a new identity with specified role.
* `PATCH /api/admin/users/:id/role`: Promote/demote role; atomically increments `tokenVersion` to sever stale privileges.
* `POST /api/admin/users/:id/deactivate`: Deactivates account and terminates all active sessions.
* `POST /api/admin/users/:id/reset-password`: Sets temporary password and increments `tokenVersion`.
* `POST /api/admin/users/:id/reset-2fa`: Emergency resets TOTP secret and clears active sessions.

---

### 4.4 Disaster Recovery & Cryptographic Backups
* `POST /api/admin/backups`: Generates an atomic snapshot bundling database tables, encrypted blobs, and HMAC-signed manifests.
* `POST /api/admin/backups/verify`: Validates snapshot manifest signature and checksums.
* `GET /api/admin/backups`: Lists stored snapshots.

---

### 4.5 NIST SP 800-88 Cryptographic Shredding
`POST /api/admin/retention/crypto-shred`

Executes multi-pass disk sanitization (cryptographic entropy overwrite + zeroing + `fdatasync`) before unlinking purged documents, eliminating physical flash/magnetic storage remanence.
