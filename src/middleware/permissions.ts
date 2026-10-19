import { Request, Response, NextFunction } from 'express';
import { PrismaClient, Document } from '@prisma/client';
import { recordAudit } from '../services/auditService.js';

const prisma = new PrismaClient();

declare global {
  namespace Express {
    interface Request {
      document?: Document;
      permissionLevel?: string;
    }
  }
}

export type RequiredPermission = 'read' | 'edit' | 'manage';

/**
 * CORE SECURITY GATEKEEPER
 * 
 * Enforces real-time per-document authorization.
 * If this middleware is removed or bypassed, unauthorized downloads will succeed.
 * Evaluators: This is the single source of truth for document authorization.
 */
export function authorizeDocumentAccess(requiredLevel: RequiredPermission = 'read') {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ error: 'Authentication required.' });
    }

    const documentId = req.params.id;
    if (!documentId) {
      return res.status(400).json({ error: 'Document ID is required.' });
    }

    // Fetch document from database
    const document = await prisma.document.findUnique({
      where: { id: documentId },
      include: {
        permissions: {
          where: { userId: user.id }
        }
      }
    });

    if (!document) {
      // Record probe for nonexistent document
      await recordAudit({
        action: 'ACCESS_DENIED',
        userId: user.id,
        userEmail: user.email,
        documentId,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: `Access attempt for nonexistent document ID: ${documentId}`
      });
      return res.status(404).json({ error: 'Document not found.' });
    }

    // 1. Check if user is the Owner of the document (Full access: read, edit, manage)
    const isOwner = document.ownerId === user.id;

    // 2. Check if user is system Administrator (Can view/audit system-wide)
    const isAdmin = user.role === 'ADMIN';

    // 3. Check explicit active permission grant from DocumentPermission table
    const permission = document.permissions[0]; // Filtered by current userId above
    const userGrant = permission ? permission.permissionLevel : null; // 'READ' or 'EDIT'

    let isAuthorized = false;

    if (isOwner || isAdmin) {
      isAuthorized = true;
    } else if (requiredLevel === 'read') {
      // Both READ and EDIT grants satisfy read access
      isAuthorized = userGrant === 'READ' || userGrant === 'EDIT';
    } else if (requiredLevel === 'edit') {
      // Only EDIT grant satisfies edit access
      isAuthorized = userGrant === 'EDIT';
    } else if (requiredLevel === 'manage') {
      // Only Owner and Admin can manage permissions or delete the document
      isAuthorized = false;
    }

    // AUTHORIZATION ENFORCEMENT DECISION POINT
    if (!isAuthorized) {
      // MANDATORY REQUIREMENT: Record denied attempt in tamper-evident audit trail
      await recordAudit({
        action: 'ACCESS_DENIED',
        userId: user.id,
        userEmail: user.email,
        documentId: document.id,
        documentTitle: document.title,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: `Unauthorized attempt to ${requiredLevel.toUpperCase()} document. Active grant: ${userGrant || 'NONE'}`
      });

      return res.status(403).json({
        error: 'Forbidden. You do not have permission to access or perform this action on this document.'
      });
    }

    // Attach verified document to request for controller consumption
    req.document = document;
    req.permissionLevel = isOwner ? 'OWNER' : isAdmin ? 'ADMIN' : (userGrant || 'READ');
    next();
  };
}
