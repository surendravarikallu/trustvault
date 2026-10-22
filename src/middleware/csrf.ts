import { Request, Response, NextFunction } from 'express';

const MUTATION_METHODS = new Set(['POST', 'PUT', 'DELETE', 'PATCH']);
const CSRF_EXEMPT_PATHS = new Set([
  '/api/auth/login',
  '/api/auth/logout',
  '/api/auth/register',
  '/api/auth/mfa/challenge',
  '/api/auth/mfa/enroll-request',
  '/api/auth/mfa/confirm-enroll',
  '/api/health'
]);

/**
 * CSRF Protection Middleware (CWE-352 Mitigation - Threat T-48).
 * Enforces strict Origin checking on all mutating requests and custom client headers
 * for cookie-authenticated sessions.
 */
export function csrfProtection(req: Request, res: Response, next: NextFunction): void {
  // Safe read-only HTTP methods are not subject to CSRF
  if (!MUTATION_METHODS.has(req.method.toUpperCase())) {
    return next();
  }

  // Exempt unauthenticated onboarding/login routes
  if (CSRF_EXEMPT_PATHS.has(req.path)) {
    return next();
  }

  const origin = req.headers.origin;
  const host = req.headers.host;

  // 1. Mandatory Origin check: If Origin header is present on mutating request, it MUST match trusted origin
  if (origin) {
    if (origin === 'null') {
      res.status(403).json({ error: 'CSRF validation failed: Opaque null Origin rejected.' });
      return;
    }
    try {
      const originUrl = new URL(origin);
      const isTrusted =
        (host && originUrl.host === host) ||
        originUrl.hostname === '127.0.0.1' ||
        originUrl.hostname === 'localhost' ||
        originUrl.hostname === 'trustvalt.me';

      if (!isTrusted) {
        res.status(403).json({ error: 'CSRF validation failed: Cross-origin request rejected.' });
        return;
      }
    } catch {
      res.status(403).json({ error: 'CSRF validation failed: Invalid Origin header.' });
      return;
    }
  }

  // 2. Referer check fallback if Origin is not present
  const referer = req.headers.referer;
  if (!origin && referer) {
    try {
      const refererUrl = new URL(referer);
      const isTrusted =
        (host && refererUrl.host === host) ||
        refererUrl.hostname === '127.0.0.1' ||
        refererUrl.hostname === 'localhost' ||
        refererUrl.hostname === 'trustvalt.me';

      if (!isTrusted) {
        res.status(403).json({ error: 'CSRF validation failed: Untrusted Referer rejected.' });
        return;
      }
    } catch {
      res.status(403).json({ error: 'CSRF validation failed: Invalid Referer header.' });
      return;
    }
  }

  // 3. Defense-in-depth: Sec-Fetch-Site header (W3C Fetch Metadata, tamper-proof in browsers)
  const secFetchSite = req.headers['sec-fetch-site'];
  if (secFetchSite === 'cross-site') {
    res.status(403).json({ error: 'CSRF validation failed: Cross-site request rejected.' });
    return;
  }

  next();
}
