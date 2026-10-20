# 🔌 TrustVault Enterprise API Reference Manual

**Base URL**: `https://trustvalt.me` (or `http://127.0.0.1:7777` in local environment)  
**Authentication Scheme**: HTTP Bearer JWT (`Authorization: Bearer <token>`)  
**Data Format**: `application/json` (Multipart for document uploads)  
**Security Standard**: Zero-Trust Gatekeeper Validation on 100% of Endpoints

---

## 1. System & Health Check Endpoints

### 1.1 Deep Health Check
`GET /api/health`

Performs an active database ping, evaluates system uptime, and reports Node.js memory allocations. Health check probes are exempt from rate limiting to prevent false degradation.

#### Response (`HTTP 200 OK`):
```json
{
  "status": "healthy",
  "system": "TrustVault Zero-Trust Security Engine",
  "timestamp": "2026-10-20T14:12:37.000Z",
  "uptimeSeconds": 1420,
  "database": {
    "status": "connected",
    "latencyMs": 1.2
  },
  "memory": {
    "rssMb": 118.6,
    "heapUsedMb": 52.3,
    "heapTotalMb": 96.5
  }
}
```

---

## 2. Authentication & MFA Endpoints (`/api/auth`)

### 2.1 Authenticate Principal (Login)
`POST /api/auth/login`

Validates user credentials against Bcrypt-12 / Argon2id salted hashes. If the account has TOTP enabled, returns an ephemeral challenge token (`mfaRequired: true`) requiring subsequent step-2 verification.

#### Request Body:
```json
{
  "email": "owner@trustvault.local",
  "password": "Owner@TrustVault2026!"
}
```

#### Response (`HTTP 200 OK` - Standard Login):
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "c1f7a8b2-3e4d-4c5b-8a7e-1a2b3c4d5e6f",
    "email": "owner@trustvault.local",
    "name": "Alice Document Owner",
    "role": "OWNER",
    "mfaEnabled": false
  }
}
```

#### Response (`HTTP 200 OK` - MFA Challenge Triggered):
```json
{
  "mfaRequired": true,
  "mfaChallengeToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

---

### 2.2 Verify TOTP Two-Factor Login
`POST /api/auth/mfa/verify-login`

Completes the two-step authentication handshake. Replay attacks are rejected if the exact same TOTP code is presented twice within the same 30-second window (CWE-287 defense).

#### Request Body:
```json
{
  "mfaChallengeToken": "<token_from_login>",
  "code": "482910"
}
```

---

## 3. Document Vault Endpoints (`/api/documents`)

### 3.1 Upload Encrypted Document
`POST /api/documents` (Requires `OWNER` or `ADMIN` role)

Accepts multipart file upload. Buffer magic bytes are evaluated to block disguised Windows PE or Linux ELF executables. Files are envelope-encrypted with AES-256-GCM before writing to vault storage.

#### Form Data Parameters:
* `file`: Binary file payload (Max: 25 MB).
* `title`: Enterprise document title (String).
* `category`: Classification category (`Legal`, `Finance`, `HR`, `Engineering`).
* `description`: Optional context or handling classification.

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
    "createdAt": "2026-10-20T14:15:00.000Z"
  }
}
```

---

### 3.2 List Vault Documents
`GET /api/documents?page=1&limit=20`

Returns documents accessible to the calling principal. Non-admin users see strictly their owned files and documents with active, unexpired clearance grants.

#### Response (`HTTP 200 OK`):
```json
{
  "total": 14,
  "page": 1,
  "limit": 20,
  "documents": [
    {
      "id": "8fa1e2b4-5c6d-4e7f-8a9b-0c1d2e3f4a5b",
      "title": "Master Services Agreement 2026",
      "category": "Legal",
      "originalFilename": "MSA_2026_Final.pdf",
      "fileSize": 412850,
      "fileHash": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
      "owner": {
        "id": "c1f7a8b2-3e4d-4c5b-8a7e-1a2b3c4d5e6f",
        "name": "Alice Document Owner",
        "email": "owner@trustvault.local"
      },
      "permissions": [
        {
          "permissionLevel": "READ",
          "expiresAt": null,
          "burnOnDownload": false,
          "previewOnly": true,
          "downloadCount": 0
        }
      ]
    }
  ]
}
```

---

### 3.3 Download or Stream In-Browser Preview
`GET /api/documents/:id/download?preview=true`

* If `preview=true`: Decrypts file in memory and streams inline for in-browser rendering. Permitted for `previewOnly` grantees.
* If `preview=false`: Streams binary download attachment. If the grant has `burnOnDownload: true`, the permission grant auto-revokes immediately upon successful download completion (`HTTP 404` on subsequent attempts).

---

### 3.4 Grant Access Clearance (Access Delegation)
`POST /api/documents/:id/permissions` (Strictly Document Owner Only)

Delegates cryptographic clearance. Non-owners (including editors and admins) receive `HTTP 403 Forbidden` (Enforced Rule L-03).

#### Request Body:
```json
{
  "targetEmail": "viewer@trustvault.local",
  "permissionLevel": "READ",
  "expiresAt": "2026-10-31T23:59:59.000Z",
  "burnOnDownload": false,
  "previewOnly": true
}
```

---

## 4. Administrative & Governance Endpoints (`/api/admin`)

### 4.1 Verify HMAC Cryptographic Audit Ledger
`GET /api/admin/audit/verify` (Admin Role Required)

Traverses all records in `AuditLog` from sequence `#1` to current head. Recomputes HMAC-SHA256 digests over all 13 canonical columns and compares against the disk-based external anchor (`storage/audit_anchor.json`).

#### Response (`HTTP 200 OK`):
```json
{
  "valid": true,
  "totalRecords": 3444,
  "headSequence": "3444",
  "headHash": "48533ba621d98fc4ef5476d05f3299761e38947f6312480376182e4f0a20042d",
  "anchorMatched": true
}
```

---

### 4.2 Emergency Password Reset & Session Invalidation
`POST /api/admin/users/:id/reset-password` (Admin Role Required)

Resets a user's password and atomically increments their `tokenVersion` in PostgreSQL, immediately invalidating all active JWT sessions on all devices.
