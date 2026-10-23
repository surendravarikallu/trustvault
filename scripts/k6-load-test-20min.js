import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '1m', target: 20 },   // Warm-up ramp: 0 to 20 VUs
    { duration: '17m', target: 35 },  // Sustained enterprise peak: 35 VUs (~150-250 req/s, simulating 5000 shift users)
    { duration: '2m', target: 0 },    // Cool-down ramp: 35 down to 0 VUs
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'],    // Under 1% errors
    http_req_duration: ['p(95)<300'],   // 95% of requests under 300ms
    http_req_duration: ['p(99)<1000'],  // 99% of requests under 1s
  },
};

const BASE_URL = 'http://127.0.0.1:7777';

export function setup() {
  console.log('--- Initializing k6 20-minute Production Load Test ---');
  console.log(`Target: ${BASE_URL}`);

  // Authenticate once as Owner to establish session cookie
  const loginRes = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({
      email: 'owner@trustvault.local',
      password: 'Owner@TrustVault2026!',
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  check(loginRes, {
    'setup login status 200': (r) => r.status === 200,
  });

  const rawCookies = loginRes.headers['Set-Cookie'] || '';
  const tokenMatch = rawCookies.match(/__Host-trustvault_token=([^;]+)/);
  const token = tokenMatch ? tokenMatch[1] : '';

  if (!token) {
    console.error('FATAL: Failed to acquire __Host-trustvault_token cookie');
  } else {
    console.log('[✓] Established authenticated session cookie for load test.');
  }

  return { token };
}

export default function (data) {
  const authHeaders = {
    headers: {
      Cookie: `__Host-trustvault_token=${data.token}`,
    },
  };

  // 1. Health Probe
  const healthRes = http.get(`${BASE_URL}/api/health`);
  check(healthRes, {
    'health check 200': (r) => r.status === 200,
  });

  // 2. Identity Verification
  const meRes = http.get(`${BASE_URL}/api/auth/me`, authHeaders);
  check(meRes, {
    'auth/me 200': (r) => r.status === 200,
  });

  // 3. Vault Document Listing (Gatekeeper Data Access Layer)
  const docsRes = http.get(`${BASE_URL}/api/documents`, authHeaders);
  check(docsRes, {
    'documents list 200': (r) => r.status === 200,
  });

  // 4. Categorized Search Query
  const filterRes = http.get(`${BASE_URL}/api/documents?category=Legal`, authHeaders);
  check(filterRes, {
    'filtered docs 200': (r) => r.status === 200,
  });

  // 5. Text Search Query
  const searchRes = http.get(`${BASE_URL}/api/documents?q=Roadmap`, authHeaders);
  check(searchRes, {
    'search docs 200': (r) => r.status === 200,
  });

  // Pacing: 250ms sleep
  sleep(0.25);
}

export function handleSummary(data) {
  return {
    'scripts/k6-summary.json': JSON.stringify(data, null, 2),
  };
}
