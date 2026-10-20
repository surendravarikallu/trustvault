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
 * Enforces custom client header and origin verification for cookie-authenticated mutating requests.
 * Pure Bearer-token API calls bypass this check as browsers never auto-attach Bearer headers.
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

  // Check if session cookie is present
  const hasCookie = req.cookies && (req.cookies['__Host-trustvault_token'] || req.cookies['trustvault_token']);
  const hasAuthHeader = req.headers.authorization && req.headers.authorization.startsWith('Bearer ');

  // If request is authenticated via Cookie (or has cookie and no Bearer token):
  if (hasCookie && !hasAuthHeader) {
    // 1. Check custom client header (set by frontend fetch wrapper; browser cross-origin cannot forge without CORS)
    const clientHeader = req.headers['x-trustvault-client'] || req.headers['x-requested-with'];
    if (clientHeader === '1' || clientHeader === 'XMLHttpRequest' || clientHeader === 'TrustVault-SPA') {
      return next();
    }

    // 2. Check Origin / Referer against host
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    const host = req.headers.host;

    if (origin) {
      try {
        const originUrl = new URL(origin);
        if (originUrl.host === host || originUrl.hostname === '127.0.0.1' || originUrl.hostname === 'localhost') {
          return next();
        }
      } catch {
        // invalid URL
      }
      res.status(403).json({ error: 'CSRF validation failed: Cross-origin request rejected.' });
      return;
    }

    if (referer) {
      try {
        const refererUrl = new URL(referer);
        if (refererUrl.host === host || refererUrl.hostname === '127.0.0.1' || refererUrl.hostname === 'localhost') {
          return next();
        }
      } catch {
        // invalid URL
      }
      res.status(403).json({ error: 'CSRF validation failed: Untrusted Referer rejected.' });
      return;
    }

    // If neither custom header nor valid Origin/Referer is provided
    res.status(403).json({
      error: 'CSRF validation failed: Missing X-TrustVault-Client header on cookie session.'
    });
    return;
  }

  // Pure Bearer tokens or non-cookie requests proceed safely
  next();
}
