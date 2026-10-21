# AI Operational Boundary & Security Guidelines

## Core Principles

When developing, auditing, or maintaining the TrustVault codebase, AI coding assistants must adhere to the following strict operational boundaries:

### 1. In-Repository Confinement
- All operations must remain strictly within the repository workspace (`c:\Users\Admin\Documents\trustvault`).
- Never inspect, query, or interact with operating system-level service configurations (e.g. Windows services, scheduled tasks, registry entries, system daemon configs).
- Never read or extract credentials from external tunnels (e.g. `cloudflared` services or Zero Trust tokens).
- If external hostnames, public URLs, or production domains are needed for testing or documentation, **ask the user directly** instead of hunting for them on the host system.

### 2. Credential & Environment Isolation
- Never read, dump, or display `.env` files, production secrets, or private keys in agent outputs, logs, or artifacts.
- Never inspect shell history files (such as `ConsoleHost_history.txt`, `.bash_history`, or PowerShell command histories).
- Always rely on mock secrets, configuration defaults, or explicit test environment variables for local testing.

### 3. Test & Database Isolation
- Test runners and automated verification scripts must strictly connect to the dedicated test database (`trustvault_test`) via `NODE_ENV=test` and `TEST_DATABASE_URL`.
- Never run ad-hoc test scripts or test suites against the live/production database (`trustvault`), as this pollutes the cryptographic audit ledger.
- The cryptographic audit anchor (`storage/audit_anchor.json`) must represent genuine production events and must never be artificially hand-written or circular-matched against test-polluted sequences.

### 4. Integrity of Reporting
- Never claim a verification is genuine if it is circular (e.g. exporting an anchor from the current database state and immediately checking against it).
- Never claim tests passed if tests were altered to pass rather than passing the security requirements.
- Always provide raw, reproducible command outputs when verifying cryptographic state, database permissions, and secret scans.
