import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  vus: 5,
  duration: '10s',
  thresholds: {
    http_req_failed: ['rate<0.01'], // < 1% errors
    http_req_duration: ['p(95)<500'], // 95% under 500ms
  },
};

const BASE_URL = 'http://127.0.0.1:7777';

export function setup() {
  const loginRes = http.post(
    `${BASE_URL}/api/auth/login`,
    JSON.stringify({
      email: 'owner@trustvault.local',
      password: 'Owner@TrustVault2026!',
    }),
    { headers: { 'Content-Type': 'application/json' } }
  );

  check(loginRes, {
    'login status 200': (r) => r.status === 200,
  });

  const rawCookies = loginRes.headers['Set-Cookie'] || '';
  const tokenMatch = rawCookies.match(/__Host-trustvault_token=([^;]+)/);
  const token = tokenMatch ? tokenMatch[1] : '';

  return { token };
}

export default function (data) {
  const authHeaders = {
    headers: {
      Cookie: `__Host-trustvault_token=${data.token}`,
    },
  };

  // 1. Health check
  const healthRes = http.get(`${BASE_URL}/api/health`);
  check(healthRes, {
    'health check status 200': (r) => r.status === 200,
  });

  // 2. Validate session (/api/auth/me)
  const meRes = http.get(`${BASE_URL}/api/auth/me`, authHeaders);
  check(meRes, {
    'auth/me status 200': (r) => r.status === 200,
  });

  // 3. Vault Documents list
  const docsRes = http.get(`${BASE_URL}/api/documents`, authHeaders);
  check(docsRes, {
    'documents list status 200': (r) => r.status === 200,
  });

  // 4. Filtered search
  const filterRes = http.get(`${BASE_URL}/api/documents?category=Legal`, authHeaders);
  check(filterRes, {
    'filtered docs status 200': (r) => r.status === 200,
  });

  sleep(0.5);
}
