export {};
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();
const BASE_URL = process.env.TARGET_URL || 'http://127.0.0.1:7777';

interface LatencyStats {
  totalRequests: number;
  successfulRequests: number;
  failedRequests: number;
  durationMs: number;
  reqPerSec: number;
  avgMs: number;
  minMs: number;
  maxMs: number;
  p50Ms: number;
  p90Ms: number;
  p95Ms: number;
  p99Ms: number;
}

function calculatePercentiles(latencies: number[]): { p50: number; p90: number; p95: number; p99: number } {
  if (latencies.length === 0) return { p50: 0, p90: 0, p95: 0, p99: 0 };
  latencies.sort((a, b) => a - b);
  const getP = (p: number) => latencies[Math.floor(latencies.length * p)] || 0;
  return {
    p50: getP(0.5),
    p90: getP(0.9),
    p95: getP(0.95),
    p99: getP(0.99)
  };
}

async function runConcurrentBatch(
  concurrency: number,
  totalRequests: number,
  requestFn: () => Promise<boolean>
): Promise<LatencyStats> {
  const latencies: number[] = [];
  let success = 0;
  let failure = 0;
  let inFlight = 0;
  let completed = 0;

  const startTime = Date.now();

  return new Promise((resolve) => {
    let started = 0;

    function next() {
      if (completed >= totalRequests) {
        const durationMs = Math.max(1, Date.now() - startTime);
        const { p50, p90, p95, p99 } = calculatePercentiles(latencies);
        const sum = latencies.reduce((a, b) => a + b, 0);
        resolve({
          totalRequests,
          successfulRequests: success,
          failedRequests: failure,
          durationMs,
          reqPerSec: Math.round((completed / (durationMs / 1000)) * 10) / 10,
          avgMs: Math.round((sum / (latencies.length || 1)) * 10) / 10,
          minMs: latencies.length ? Math.min(...latencies) : 0,
          maxMs: latencies.length ? Math.max(...latencies) : 0,
          p50Ms: Math.round(p50 * 10) / 10,
          p90Ms: Math.round(p90 * 10) / 10,
          p95Ms: Math.round(p95 * 10) / 10,
          p99Ms: Math.round(p99 * 10) / 10
        });
        return;
      }

      while (inFlight < concurrency && started < totalRequests) {
        started++;
        inFlight++;
        const reqStart = Date.now();
        requestFn()
          .then((ok) => {
            const reqDuration = Date.now() - reqStart;
            latencies.push(reqDuration);
            if (ok) success++;
            else failure++;
          })
          .catch(() => {
            const reqDuration = Date.now() - reqStart;
            latencies.push(reqDuration);
            failure++;
          })
          .finally(() => {
            inFlight--;
            completed++;
            next();
          });
      }
    }

    next();
  });
}

async function loginAndGetToken(email: string, password: string): Promise<string> {
  const res = await fetch(`${BASE_URL}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  if (!res.ok || !data.token) {
    throw new Error(`Login failed for ${email}: ${JSON.stringify(data)}`);
  }
  return data.token;
}

async function main() {
  console.log('================================================================');
  console.log(' TrustVault Production Performance & Concurrency Benchmark');
  console.log('================================================================');

  // 1. Inspect PostgreSQL Database
  console.log('\n--- 1. PostgreSQL Database Configuration & Health ---');
  try {
    const maxConn: any = await prisma.$queryRawUnsafe('SHOW max_connections');
    const sharedBuffers: any = await prisma.$queryRawUnsafe('SHOW shared_buffers');
    const workMem: any = await prisma.$queryRawUnsafe('SHOW work_mem');
    const activeConn: any = await prisma.$queryRawUnsafe('SELECT count(*) as count FROM pg_stat_activity');
    const pgVersion: any = await prisma.$queryRawUnsafe('SELECT version()');

    console.log(`[✓] PostgreSQL Version: ${pgVersion[0].version.split(',')[0]}`);
    console.log(`[✓] max_connections:     ${maxConn[0].max_connections}`);
    console.log(`[✓] shared_buffers:      ${sharedBuffers[0].shared_buffers}`);
    console.log(`[✓] work_mem:            ${workMem[0].work_mem}`);
    console.log(`[✓] Active Connections:  ${activeConn[0].count}`);

    const [userCount, docCount, permCount, auditCount] = await Promise.all([
      prisma.user.count(),
      prisma.document.count(),
      prisma.documentPermission.count(),
      prisma.auditLog.count()
    ]);
    console.log(`[✓] Total Users:          ${userCount}`);
    console.log(`[✓] Total Documents:      ${docCount}`);
    console.log(`[✓] Total Permissions:    ${permCount}`);
    console.log(`[✓] Total Audit Records:  ${auditCount}`);
  } catch (err: any) {
    console.error('[!] Database inspection error:', err.message);
  }

  // 2. Obtain tokens for personas
  console.log('\n--- 2. Establishing Authentication Sessions ---');
  let adminToken = '';
  let ownerToken = '';
  let viewerToken = '';

  try {
    adminToken = await loginAndGetToken('admin@trustvault.local', 'Admin@TrustVault2026!');
    console.log('[✓] Admin authenticated.');
    ownerToken = await loginAndGetToken('owner@trustvault.local', 'Owner@TrustVault2026!');
    console.log('[✓] Owner authenticated.');
    viewerToken = await loginAndGetToken('viewer@trustvault.local', 'Viewer@TrustVault2026!');
    console.log('[✓] Viewer authenticated.');
  } catch (err: any) {
    console.error('[!] Authentication failure:', err.message);
    process.exit(1);
  }

  // 3. Test Health Check Concurrency (Node Event Loop + DB Ping)
  console.log('\n--- 3. Stress Test: Health Check Endpoint (Node.js + PostgreSQL Round-Trip) ---');
  const healthLevels = [10, 50, 100, 200];
  for (const c of healthLevels) {
    const total = c * 10;
    const stats = await runConcurrentBatch(c, total, async () => {
      const res = await fetch(`${BASE_URL}/api/health`);
      return res.ok;
    });
    console.log(
      `  Concurrency ${c.toString().padEnd(3)} | ${total} reqs | ` +
      `Throughput: ${stats.reqPerSec.toFixed(1)} req/s | ` +
      `Avg: ${stats.avgMs}ms | p50: ${stats.p50Ms}ms | p95: ${stats.p95Ms}ms | p99: ${stats.p99Ms}ms | ` +
      `Success: ${stats.successfulRequests}/${total}`
    );
  }

  // 4. Test Authenticated Vault Document Queries (JWT + DB Token Version + DAL Visibility Filter)
  console.log('\n--- 4. Stress Test: Authenticated Document Listing (Zero-Trust DAL Isolation) ---');
  const docLevels = [10, 25, 50, 100];
  for (const c of docLevels) {
    const total = c * 5;
    const stats = await runConcurrentBatch(c, total, async () => {
      const res = await fetch(`${BASE_URL}/api/documents`, {
        headers: { Authorization: `Bearer ${viewerToken}` }
      });
      return res.ok;
    });
    console.log(
      `  Concurrency ${c.toString().padEnd(3)} | ${total} reqs | ` +
      `Throughput: ${stats.reqPerSec.toFixed(1)} req/s | ` +
      `Avg: ${stats.avgMs}ms | p50: ${stats.p50Ms}ms | p95: ${stats.p95Ms}ms | p99: ${stats.p99Ms}ms | ` +
      `Success: ${stats.successfulRequests}/${total}`
    );
  }

  // 5. Test Cryptographic Audit Verification (HMAC-SHA256 sequential verification across ledger)
  console.log('\n--- 5. Stress Test: HMAC Audit Ledger Verification (Full Chain Traversal) ---');
  const auditStart = Date.now();
  const auditRes = await fetch(`${BASE_URL}/api/admin/audit/verify`, {
    headers: { Authorization: `Bearer ${adminToken}` }
  });
  const auditDuration = Date.now() - auditStart;
  const auditData = await auditRes.json();
  console.log(`[✓] Audit verification completed in ${auditDuration}ms:`);
  console.log(`    Valid: ${auditData.valid} | Total Verified Records: ${auditData.totalRecords}`);

  // 6. Summary of Capacity Analysis
  console.log('\n================================================================');
  console.log(' Benchmark Completed Successfully');
  console.log('================================================================');
}

main()
  .catch(console.error)
  .finally(() => prisma.$disconnect());
