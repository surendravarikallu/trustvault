# TrustVault — Zero-Trust Document Security Engine

TrustVault is a zero-trust enterprise document management system built with Node.js, Express, TypeScript, PostgreSQL, Prisma, and React. It is engineered specifically for defensive security, cryptographic audit integrity, and mutation-tested authorization controls.

---

## 1. Credentials for Evaluation & Testing

The system is seeded with dedicated accounts for each evaluation persona:

| Role | Email | Password | Default System Capabilities |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin@trustvault.local` | `Admin@TrustVault2026!` | Audit verification, user role management, system metrics. **Cannot view file contents without owner grant.** |
| **Document Owner**| `owner@trustvault.local` | `Owner@TrustVault2026!` | Upload documents, edit metadata, replace file versions, grant/revoke permissions, AI reviewer suggestions. |
| **Authorized Viewer** | `viewer@trustvault.local`| `Viewer@TrustVault2026!` | Read metadata and download explicitly granted documents (`MSA_Acme_2026.pdf`). Cannot upload or re-share. |
| **Adversary (Eve)** | `eve@trustvault.local` | `Eve@TrustVault2026!` | Registered viewer with zero document grants. Used in automated tests to attempt unauthorized access. |

---

## 2. Key Architecture & Security Invariants

- **Enforced Data Access Layer (DAL):** All document access is mediated through `src/dal/documentDal.ts` using `loadDocumentFor(user, id, action, reqContext)` with an ESLint boundary rule (`no-restricted-imports`) prohibiting direct database queries in controllers.
- **Passing Mutation Testing:** Removing authorization checks immediately causes security route test suites to fail (RED). Verified via `npm run test:mutation`.
- **Three-Tier Role Hierarchy:** `ADMIN`, `OWNER`, and `VIEWER` with strict privilege boundaries. Public registration creates `VIEWER` (upload disabled); `OWNER` status requires admin promotion.
- **Owner-Exclusive Sharing:** Editors cannot re-share; Admins cannot view file contents or grant themselves access without explicit document owner authorization.
- **Cryptographic Audit Ledger:** HMAC-SHA256 hash-chained ledger storing unconstrained document references (preventing existence oracles and delete-time history mutation). Writes are serialized with PostgreSQL advisory transaction locks (`pg_advisory_xact_lock`) and verified against external anchors (`storage/audit_anchor.json`).
- **Instant Revocation:** `tokenVersion` on user records immediately invalidates active JWTs upon role demotion, deactivation, or logout.

---

## 3. Quick Start & Verification

### Prerequisites
- Node.js (v20+ LTS)
- PostgreSQL 18 running on `localhost:5432`

### Setup Database & Dependencies
```bash
# Install dependencies
npm install

# Push schema to database
npm run db:push

# Apply PostgreSQL dual-role and immutability trigger
# (Executed automatically or manually via prisma/setup-roles.sql)

# Seed initial test data and audit ledger
npm run db:seed
```

### Run Tests & Verification
```bash
# Run full 16-suite automated security tests
npm test

# Run mutation verification tool (proves tests go RED if check is removed)
npm run test:mutation

# Run ESLint boundary check (asserts zero Prisma imports in controllers)
npm run lint
```

### Start Development Server & Tunnel
```bash
# Start local Express server (bound to 127.0.0.1:5000)
npm run dev

# Expose server via Cloudflare Tunnel
npm run tunnel
```

---

## 4. Core Documentation

- **[`IMPLEMENTATION_PLAN.md`](./IMPLEMENTATION_PLAN.md):** Complete architectural analysis, 19 cataloged loopholes & exact fixes, and phased roadmap.
- **[`THREATS.md`](./THREATS.md):** Catalog of modeled threat vectors (T-01 to T-32) mapped to automated tests and defenses.
- **[`PROMPTS.md`](./PROMPTS.md):** Human engineering oversight log documenting AI flaws identified, architectural corrections, and Git commit references.
- **[`CONTEXT_HANDOVER.md`](./CONTEXT_HANDOVER.md):** Architectural handover and database schemas.
