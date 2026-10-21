import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { Role } from '../dal/types';
import { config } from '../config';
import { getUserById } from '../dal/userDal';
import { getCachedUserSessionAsync, setCachedUserSession } from '../utils/sessionCache';

export interface AuthenticatedUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  tokenVersion: number;
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

interface JwtPayload {
  userId: string;
  tokenVersion: number;
}

/**
 * Authentication Middleware.
 * Supports dual-channel: HttpOnly Cookies and Authorization: Bearer.
 * Defense against Loophole L-01: Privilege Demotion Lag & Token Replay.
 */
export async function authenticate(req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> {
  let token: string | undefined;

  // Single credential path: Strictly __Host-trustvault_token cookie
  if (req.cookies) {
    token = req.cookies['__Host-trustvault_token'];
  }

  if (!token) {
    res.status(401).json({ error: 'Authentication required. Missing secure __Host- session cookie.' });
    return;
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] }) as JwtPayload;

    if (!decoded.userId) {
      res.status(401).json({ error: 'Invalid token payload.' });
      return;
    }

    // Re-verify against database state with Redis-backed micro-cache acceleration
    let user = await getCachedUserSessionAsync(decoded.userId);
    if (!user) {
      const dbUser = await getUserById(decoded.userId);
      if (dbUser) {
        setCachedUserSession(dbUser);
        user = {
          id: dbUser.id,
          email: dbUser.email,
          name: dbUser.name,
          role: dbUser.role,
          tokenVersion: dbUser.tokenVersion,
          isActive: dbUser.isActive,
          cachedAt: Date.now()
        };
      }
    }

    if (!user || !user.isActive) {
      res.status(401).json({ error: 'User account is inactive or does not exist.' });
      return;
    }

    // Instant Revocation check: Token version must match current DB version
    if (decoded.tokenVersion !== user.tokenVersion) {
      res.status(401).json({ error: 'Session revoked. User role was changed or session was invalidated.' });
      return;
    }

    req.user = {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      tokenVersion: user.tokenVersion
    };

    next();
  } catch (error: any) {
    res.status(401).json({ error: 'Invalid or expired authentication token.' });
  }
}

/**
 * Role-Based Access Control Middleware.
 */
export function requireRole(allowedRoles: Role[]) {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
    if (!req.user) {
      res.status(401).json({ error: 'Authentication required.' });
      return;
    }

    if (!allowedRoles.includes(req.user.role)) {
      res.status(403).json({ error: `Access forbidden. Required role: ${allowedRoles.join(' or ')}.` });
      return;
    }

    next();
  };
}
