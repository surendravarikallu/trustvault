# TrustVault — AI Prompt Engineering & Oversight Log (`PROMPTS.md`)

This log documents how AI tools were directed throughout the development of **TrustVault**, capturing critical instances where the AI proposed insecure, naive, or flawed patterns, what was specifically wrong with those proposals, and how they were corrected in the repository.

---

## Reusable System Instructions / Context Used
The following guidelines were provided to the AI assistant to enforce security-first standards:
> *"Every access decision must be server-side enforced in real-time. No authorization decisions may rely on client-side state, unrevocable tokens, or hidden UI elements. All document streams must pass through an authentication and permission verification gatekeeper, and all refused access attempts must be logged to an append-only audit trail."*

---

## Dated Prompt Entries

### Entry 1: Secure File Storage & Direct URL Exposure (Day 1 - 2026-10-19)
- **What I asked for**:
  *"Create an Express route to handle file uploads and serve uploaded documents to authenticated users."*
- **What the AI produced**:
  The AI set up `multer` storing files directly into a public `public/uploads/` directory with their original filenames (e.g. `public/uploads/salary_review.pdf`) and used `express.static('public')` to serve them. The AI then suggested returning `http://localhost:5000/uploads/salary_review.pdf` in the API response.
- **What was wrong with it**:
  1. **Direct Static Storage Exposure (THREAT-03)**: Anyone who guesses or scrapes the file URL could download the document directly from the web server without passing through any authentication or authorization checks.
  2. **Filename Collision & Path Traversal**: Storing original filenames risks overwriting files or malicious directory traversal (e.g. `../../etc/passwd`).
  3. **Zero Audit Visibility**: Direct static downloads bypass Express middleware entirely, meaning no audit log is created when a user accesses the file.
- **What I did instead**:
  1. Relocated storage to a dedicated, non-public directory (`storage/uploads/`).
  2. Stored files using cryptographically random UUIDv4 identifiers without original extensions on the disk.
  3. Removed static file serving middleware for the uploads directory.
  4. Implemented an authenticated, authorized streaming endpoint: `GET /api/documents/:id/download` that verifies permissions and logs the access before piping file bytes via `res.sendFile()`.
- **Commit**: `[Initial architecture & secure storage]`

---

### Entry 2: Permission Revocation & The JWT Trap (Day 1 - 2026-10-19)
- **What I asked for**:
  *"Design the authentication and permission token mechanism so the frontend knows what documents a user can read or edit without making frequent database requests."*
- **What the AI produced**:
  The AI suggested embedding the user's document permissions directly into the signed JWT access token:
  ```json
  {
    "userId": "usr_bob",
    "role": "viewer",
    "permissions": { "doc_101": "read", "doc_102": "edit" },
    "exp": 1729382400
  }
  ```
  The AI claimed this was optimal because it avoided database lookups on every file download.
- **What was wrong with it (THREAT-02)**:
  1. **Violates Requirement 3 ("Taking access away works immediately")**: If an owner revokes Bob's access to `doc_101`, Bob's JWT still asserts he has `read` access until the token expires (hours later).
  2. **Unbounded Token Size**: In an enterprise document vault with hundreds of accessible documents, the JWT header would exceed HTTP header size limits.
  3. **Inability to Prove Immediate Revocation**: In an audit, you cannot prove that access stopped the second it was revoked if stale tokens remain valid.
- **What I did instead**:
  1. Restricted the JWT strictly to user identity (`userId`, `email`, `role`).
  2. Enforced real-time authorization checks in `src/middleware/permissions.ts`. Every request to read, download, or edit queries the `DocumentPermission` table directly.
  3. Tested that invoking the revocation endpoint instantly yields a `403 Forbidden` on the very next millisecond download attempt.
- **Commit**: `[Real-time DB permission checks & instant revocation]`

---

### Entry 3: Audit Trail Tamper-Evidence & Failed Access Attempts (Day 1 - 2026-10-19)
- **What I asked for**:
  *"Implement an audit logging service that tracks when documents are uploaded, downloaded, and updated."*
- **What the AI produced**:
  A basic database model `AuditLog` with standard fields (`id`, `userId`, `action`, `documentId`, `timestamp`) and a service that called `prisma.auditLog.create(...)` on successful controller actions.
- **What was wrong with it (THREAT-04 & THREAT-08)**:
  1. **Silent Refusals**: The AI only logged *successful* actions inside the controllers. It completely omitted logging when a user was **refused** access or attempted unauthorized access. Snovasys explicitly requires: *"prove who reached it... including the attempts that were refused."*
  2. **Mutable Audit Trail**: A database administrator or an attacker with SQL injection could quietly execute `UPDATE audit_logs SET ...` or `DELETE FROM audit_logs WHERE ...` to cover their tracks without any detection.
- **What I did instead**:
  1. Hooked the audit logger directly into the `verifyDocumentAccess` middleware to record `ACCESS_DENIED` events with IP address and target document whenever an authorization check fails.
  2. Implemented cryptographic SHA-256 hash chaining: every audit record hashes its own content combined with the `previousHash` of the prior log entry, forming a tamper-evident blockchain-style ledger.
  3. Built an integrity verification endpoint that re-verifies the entire chain to detect any altered or deleted records.
- **Commit**: `[Cryptographic hash-chained audit trail with denied access logging]`

---

*(Additional entries will be logged as development proceeds across the week)*
