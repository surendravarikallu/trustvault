# 📚 TrustVault Enterprise Documentation Suite

Welcome to the **TrustVault Zero-Trust Cryptographic Document Vault** engineering and production documentation suite. This directory contains production-grade specifications, scaling blueprints, stress testing forensic reports, database architecture references, and API manuals matching top-tier enterprise standards.

---

## 📑 Documentation Index

| Document | Primary Audience | Description | Key Focus Areas |
| :--- | :--- | :--- | :--- |
| **[SCALING_GUIDE_5000_USERS.md](./SCALING_GUIDE_5000_USERS.md)** | DevOps / SRE / Lead Architects | Production scaling blueprint to support **5,000+ concurrent enterprise users** on Windows Server host. | Little's Law, PM2 Clustering, Windows TCP Tuning, Prisma Singleton, Advisory Locks. |
| **[STRESS_TEST_REPORT.md](./STRESS_TEST_REPORT.md)** | QA / Security Evaluators | Forensic concurrency and benchmark results across 3,600+ requests. | 100% Success Rate, 2,463 req/s throughput, p50/p95 latency, HMAC chain verification in 97ms. |
| **[DATABASE_SCHEMA.md](./DATABASE_SCHEMA.md)** | Database Administrators / DBAs | Complete PostgreSQL 18 data dictionary, index topology, and query plans. | EXPLAIN ANALYZE, Dual-Role Security (`trustvault_app` REVOKE), B-Tree indexes, Connection Pooling. |
| **[SYSTEM_DESIGN_DOCUMENT.md](./SYSTEM_DESIGN_DOCUMENT.md)** | Architects / SecOps Engineers | High-level system architecture, cryptographic data flows, and zero-trust invariants. | AES-256-GCM Envelope Encryption, Fail-Closed 404 Shielding, Burn-on-Download, NIST SP 800-88. |
| **[API_REFERENCE.md](./API_REFERENCE.md)** | Integration Engineers / Developers | Comprehensive REST API manual with request/response schemas and authentication headers. | JWT Bearer Auth, MFA Verification, Document Ingestion, Stream Previews, HMAC Ledger Audits. |

---

## 🎯 Quick Architecture Reference

* **Host Environment**: Windows Server (`Akshar-ErpServer`: 12 vCPU cores, 32GB RAM)
* **Ingress**: Bound to `127.0.0.1:7777` with Cloudflare Tunnel Edge Termination
* **Database**: PostgreSQL 18.3 (`max_connections = 500`) with Single Coordinated Connection Pool
* **Security Model**: Single Gatekeeper Data Access Layer (DAL) enforcing 100% zero-trust authorization
* **Cryptographic Ledger**: Monotonic HMAC-SHA256 hash chaining with external disk anchoring
