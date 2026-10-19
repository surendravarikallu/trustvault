import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { PrismaClient } from '@prisma/client';
import { config } from '../config.js';
import { recordAudit } from '../services/auditService.js';

const prisma = new PrismaClient();

export interface AuthenticatedUser {
  id: string;
  email: string;
  name: string;
  role: string; // ADMIN, OWNER, VIEWER
}

declare global {
  namespace Express {
    interface Request {
      user?: AuthenticatedUser;
    }
  }
}

/**
 * Validates JWT access token and attaches active user record to the request
 */
export async function authenticateToken(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  let token: string | undefined;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.split(' ')[1];
  } else if (req.query.token && typeof req.query.token === 'string') {
    // Ephemeral token parameter for file downloads if needed
    token = req.query.token;
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token, config.jwtSecret) as { id: string; email: string };

    // Verify user still exists in database (prevents stale access if account was deleted)
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: { id: true, email: true, name: true, role: true }
    });

    if (!user) {
      return res.status(401).json({ error: 'User account not found or has been deactivated.' });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Invalid or expired token.' });
  }
}

/**
 * Enforces role-based permissions (ADMIN, OWNER, VIEWER)
 */
export function requireRole(...allowedRoles: string[]) {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    if (!allowedRoles.includes(req.user.role)) {
      // Record denied administrative attempt
      await recordAudit({
        action: 'ACCESS_DENIED',
        userId: req.user.id,
        userEmail: req.user.email,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: `Role '${req.user.role}' attempted action requiring [${allowedRoles.join(', ')}]`
      });

      return res.status(403).json({
        error: `Forbidden. Role '${req.user.role}' lacks required permissions.`
      });
    }

    next();
  };
}
