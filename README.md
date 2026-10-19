# TrustVault 🛡️ — Secure Document Sharing with a Real Audit Trail

> **Snovasys Fresher Hiring Challenge 2026**  
> Candidate: **Varikallu Surendra**  
> Deployed Live URL: *(Provided upon deployment)*  
> Repository: Public Git with chronological commit history across the week.

---

## 1. System Overview & The Core Security Model

Traditional document sharing systems fail in two expensive ways:
1. **Permission Leaks & Zombie Grants**: Access granted for a single file leaks entire folders; revoked users retain valid access via cached credentials or static URLs.
2. **Untrusted Audit Records**: In the event of a breach, organizations cannot reliably prove *who accessed what and when*, or whether audit logs were quietly altered by privileged insiders.

**TrustVault** solves this by treating document sharing as a **security problem wearing the clothes of a CRUD application**:
- **Zero Static File Exposure**: Files are stored outside web roots under random UUIDv4 names without file extensions. File binaries can only be retrieved through a real-time authorized stream controller.
- **Instant Revocation Without Lag**: Permissions are evaluated directly in the database at the exact millisecond of request execution. No permissions are stored in stateless JWT tokens. When an owner revokes access, any subsequent attempt immediately returns `403 Forbidden`.
- **Tamper-Evident Cryptographic Audit Ledger**: Every action (and every **refused attempt**) is recorded in an append-only ledger where each row contains a SHA-256 hash chained to the previous record (`hash = SHA256(seq + timestamp + action + user + doc + status + prevHash)`). Any database alteration or record deletion breaks the cryptographic chain.
- **Server-Side Enforcement**: No trust in client state or hidden UI buttons. The server verifies identity, ownership, and active grants on every route.

---

## 2. Seed Credentials for Live Evaluation

The system comes pre-seeded with accounts for all roles:

| Role | Email | Password | Allowed Capabilities |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@trustvault.com` | `AdminPassword123!` | System-wide audit inspection, cryptographic integrity verification, telemetry, view all documents. |
| **Document Owner** | `alice.owner@trustvault.com` | `OwnerPassword123!` | Upload documents, grant `READ` or `EDIT` permissions to named users, revoke access instantly, delete owned files. |
| **Viewer (Authorized)** | `bob.viewer@trustvault.com` | `ViewerPassword123!` | View and download documents explicitly granted to him by owners. Cannot grant permissions or delete. |
| **Viewer (Intruder/Unrelated)** | `eve.intruder@trustvault.com` | `EvePassword123!` | Unrelated user used to test cross-tenant isolation. Blocked (`403`) from accessing Alice's confidential documents. |

---

## 3. API Reference & Authorization Matrix

| Method | Endpoint | Required Role / Permission | Purpose | Audit Log Event |
| :--- | :--- | :--- | :--- | :--- |
| `POST` | `/api/auth/register` | Public | Register new user account | `LOGIN_SUCCESS` |
| `POST` | `/api/auth/login` | Public | Authenticate user & issue JWT | `LOGIN_SUCCESS` / `LOGIN_FAILED` |
| `GET` | `/api/auth/me` | Authenticated | Get current session user profile | None |
| `GET` | `/api/documents` | Authenticated | List accessible documents (filtered by user ownership/grants) | None |
| `POST` | `/api/documents` | Authenticated (`OWNER` or `ADMIN`) | Upload file with magic byte validation | `UPLOAD` |
| `GET` | `/api/documents/:id` | `READ`, `EDIT`, `OWNER`, `ADMIN` | Get document metadata | `ACCESS_DENIED` on failure |
| `GET` | `/api/documents/:id/download` | `READ`, `EDIT`, `OWNER`, `ADMIN` | Stream file binary | `DOWNLOAD` or `ACCESS_DENIED` |
| `DELETE` | `/api/documents/:id` | `OWNER` or `ADMIN` | Delete document binary and database records | `DELETE` or `ACCESS_DENIED` |
| `POST` | `/api/documents/:id/permissions` | `OWNER` or `ADMIN` | Grant `READ` or `EDIT` permission to a named user | `GRANT_PERMISSION` |
| `DELETE` | `/api/documents/:id/permissions/:userId` | `OWNER` or `ADMIN` | Instantly revoke access from a named user | `REVOKE_PERMISSION` |
| `GET` | `/api/documents/:id/permissions` | `READ`, `EDIT`, `OWNER`, `ADMIN` | List all active grants on this document | None |
| `GET` | `/api/admin/audit-logs` | `ADMIN` | Retrieve paginated audit trail logs | None |
| `GET` | `/api/admin/audit-verify` | `ADMIN` | Verify SHA-256 cryptographic hash chain integrity | None |
| `GET` | `/api/admin/metrics` | `ADMIN` | Security telemetry and denied attack metrics | None |

---

## 4. Setup & Running from a Clean Clone

### Prerequisites
- Node.js v18+ (tested on v24.10)
- npm v9+

### Steps
```bash
# 1. Clone repository
git clone <repo-url>
cd trustvault

# 2. Install dependencies
npm install

# 3. Configure environment
cp .env.example .env

# 4. Initialize database schema and generate Prisma client
npx prisma db push

# 5. Seed default users, demo confidential files, and genesis audit logs
npm run db:seed

# 6. Run automated security test suite
npm test

# 7. Start the development server
npm run dev
```
The server will start on `http://localhost:5000`.

---

## 5. Security Architecture & Threat Model (`THREATS.md`)

Our threat matrix details 10 attack vectors analyzed and mitigated:
- **THREAT-01 (IDOR)**: Mitigated by `src/middleware/permissions.ts`.
- **THREAT-02 (Zombie Tokens / Revocation Lag)**: Zero permissions cached in JWTs; real-time DB queries.
- **THREAT-03 (Direct Storage Exposure)**: Random UUID files stored outside web root without extensions.
- **THREAT-04 (Audit Tampering)**: SHA-256 hash chaining prevents log alteration/erasure.
- **THREAT-05 (Privilege Escalation)**: Explicit role and ownership verification on all mutations.
- **THREAT-06 (Disguised File Uploads)**: Multi-layer extension whitelist and binary magic bytes inspection (`file-type`).
- **THREAT-07 (Search Metadata Leakage)**: Row-level SQL filtering (`WHERE ownerId = user.id OR id IN (permissions)`).
- **THREAT-08 (Reconnaissance / Silent Probes)**: All unauthorized access attempts are logged as `ACCESS_DENIED` with IP and document ID before returning HTTP 403.

For full details, refer to [`THREATS.md`](file:///c:/Users/suren/OneDrive/Documents/Snovasys/THREATS.md).

---

## 6. AI Oversight & Prompt Journal (`PROMPTS.md`)

Documented chronologically across the week in [`PROMPTS.md`](file:///c:/Users/suren/OneDrive/Documents/Snovasys/PROMPTS.md). Highlights where AI suggestions were caught and corrected:
1. **AI proposed static `/uploads/:filename` serving**: Caught and replaced with private UUID streaming controller.
2. **AI proposed storing permission claims inside JWT**: Caught due to inability to revoke access immediately; replaced with real-time database checks.
3. **AI only logged successful operations**: Caught omission of refused access attempts and lack of tamper evidence; replaced with cryptographic hash chaining and denied attempt tracking.

---

## 7. Shortlisted Candidate Walkthrough Note

> **Where the authorization decision is made**:  
> In [`src/middleware/permissions.ts`](file:///c:/Users/suren/OneDrive/Documents/Snovasys/src/middleware/permissions.ts#L30-L100) inside the `authorizeDocumentAccess` middleware.
> 
> **What would happen if that line were removed**:  
> Removing the permission check would allow any authenticated user to download any document simply by passing its UUID (`IDOR` vulnerability). Our automated security test `THREAT-01` in `tests/security.test.ts` immediately fails if this middleware is bypassed.
