import request from 'supertest';
import { app } from '../src/server';

/**
 * Creates a Supertest agent patched to automatically retain and send Secure __Host- cookies over local HTTP test runs.
 */
export function createTestAgent(appInstance = app) {
  const agent = request.agent(appInstance);
  const origGet = agent.jar.getCookies;
  agent.jar.getCookies = function (access: any) {
    if (access) access.secure = true;
    return origGet.call(this, access);
  };
  return agent;
}

/**
 * Logs in as a specific user and extracts the raw __Host-trustvault_token cookie string.
 */
export async function getAuthCookie(
  email: string,
  password = getDefaultPassword(email),
  appInstance = app
): Promise<string> {
  const res = await request(appInstance)
    .post('/api/auth/login')
    .send({ email, password });

  const setCookie = res.headers['set-cookie'];
  if (!setCookie) {
    throw new Error(`Failed to login as ${email}: ${JSON.stringify(res.body)}`);
  }

  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return raw.split(';')[0];
}

export function getDefaultPassword(email: string): string {
  const prefix = email.split('@')[0];
  const cap = prefix.charAt(0).toUpperCase() + prefix.slice(1);
  return `${cap}@TrustVault2026!`;
}

export function extractAuthCookie(res: any): string {
  const setCookie = res.headers['set-cookie'];
  if (!setCookie) throw new Error('No set-cookie header found in response');
  const raw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  return raw.split(';')[0];
}
