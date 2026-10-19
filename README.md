# TrustVault — Zero-Trust Document Security Engine

TrustVault is a zero-trust enterprise document management system built with Node.js, Express, TypeScript, PostgreSQL, Prisma, and React. It is engineered specifically for defensive security, audit integrity, and mutation-tested authorization controls.

---

## Key Architecture & Security Specifications

- **Enforced Data Access Layer (DAL):** All document access is mediated through `src/dal/documentDal.ts` using `loadDocumentFor(user, id, action, reqContext)` with an ESLint boundary rule (`no-restricted-imports`) prohibiting direct database queries in controllers.
- **Passing Mutation Testing:** Removing authorization checks immediately causes security route test suites to fail (RED).
- **Three-Tier Role Hierarchy:** `ADMIN`, `OWNER`, and `VIEWER` with strict privilege boundaries. Public registration creates `VIEWER` (upload disabled); `OWNER` status requires admin promotion.
- **Owner-Exclusive Sharing:** Editors cannot re-share; Admins cannot view file contents or grant themselves access without explicit document owner authorization.
- **Cryptographic Audit Ledger:** HMAC-SHA256 hash-chained ledger storing unconstrained document references (preventing existence oracles and delete-time history mutation). Writes are serialized with PostgreSQL advisory transaction locks (`pg_advisory_xact_lock`) and verified against external anchors (`storage/audit_anchor.json`).
- **Instant Revocation:** `tokenVersion` on user records immediately invalidates active JWTs upon role demotion, deactivation, or logout.

---

## Core Documentation

- **[CONTEXT_HANDOVER.md](./CONTEXT_HANDOVER.md):** Complete technical context, architectural invariants, Prisma schema, endpoints matrix, and day-by-day implementation guide.
- **[THREATS.md](./THREATS.md):** Catalog of 23 modeled threat vectors (T-01 to T-23) mapped to automated tests and defenses.
- **[PROMPTS.md](./PROMPTS.md):** Human engineering oversight log documenting AI flaws identified, architectural corrections, and commit references.

---

## Quick Start & Verification

```bash
# Clone the repository
git clone https://github.com/surendravarikallu/trustvault.git
cd trustvault

# Review architecture & handover notes
cat CONTEXT_HANDOVER.md
```
