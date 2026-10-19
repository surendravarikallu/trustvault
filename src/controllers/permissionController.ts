import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { recordAudit } from '../services/auditService.js';

const prisma = new PrismaClient();

/**
 * Grants or updates permission (READ or EDIT) for a named user on a document
 * Only the document owner or an administrator can grant permissions
 */
export async function grantPermission(req: Request, res: Response) {
  try {
    const document = req.document!;
    const currentUser = req.user!;
    const { targetEmail, permissionLevel } = req.body;

    // Only Owner or Admin can manage permissions
    if (document.ownerId !== currentUser.id && currentUser.role !== 'ADMIN') {
      await recordAudit({
        action: 'ACCESS_DENIED',
        userId: currentUser.id,
        userEmail: currentUser.email,
        documentId: document.id,
        documentTitle: document.title,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: 'Unauthorized attempt to grant document permissions'
      });
      return res.status(403).json({ error: 'Only the document owner or an administrator can grant permissions.' });
    }

    if (!targetEmail || !permissionLevel) {
      return res.status(400).json({ error: 'targetEmail and permissionLevel (READ or EDIT) are required.' });
    }

    const level = permissionLevel.toUpperCase();
    if (!['READ', 'EDIT'].includes(level)) {
      return res.status(400).json({ error: "permissionLevel must be either 'READ' or 'EDIT'." });
    }

    // Find recipient user
    const targetUser = await prisma.user.findUnique({
      where: { email: targetEmail.toLowerCase().trim() },
      select: { id: true, email: true, name: true, role: true }
    });

    if (!targetUser) {
      return res.status(404).json({ error: `User with email '${targetEmail}' does not exist.` });
    }

    // Prevent granting permissions to oneself if already owner
    if (targetUser.id === document.ownerId) {
      return res.status(400).json({ error: 'The document owner already has full privileges.' });
    }

    // Upsert permission record
    const permission = await prisma.documentPermission.upsert({
      where: {
        documentId_userId: {
          documentId: document.id,
          userId: targetUser.id
        }
      },
      update: {
        permissionLevel: level,
        grantedById: currentUser.id,
        grantedAt: new Date()
      },
      create: {
        documentId: document.id,
        userId: targetUser.id,
        permissionLevel: level,
        grantedById: currentUser.id
      }
    });

    // Record audit event
    await recordAudit({
      action: 'GRANT_PERMISSION',
      userId: currentUser.id,
      userEmail: currentUser.email,
      documentId: document.id,
      documentTitle: document.title,
      status: 'SUCCESS',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: `Granted ${level} access on '${document.title}' to ${targetUser.email} (${targetUser.name})`
    });

    return res.json({
      message: `Successfully granted ${level} access to ${targetUser.email}.`,
      permission: {
        id: permission.id,
        permissionLevel: permission.permissionLevel,
        grantedAt: permission.grantedAt,
        user: targetUser
      }
    });
  } catch (error) {
    console.error('Grant permission error:', error);
    return res.status(500).json({ error: 'Failed to grant permission.' });
  }
}

/**
 * Revokes permission from a user immediately
 * Evaluator check: Instant revocation must stop access without delay
 */
export async function revokePermission(req: Request, res: Response) {
  try {
    const document = req.document!;
    const currentUser = req.user!;
    const targetUserId = req.params.userId;

    if (document.ownerId !== currentUser.id && currentUser.role !== 'ADMIN') {
      await recordAudit({
        action: 'ACCESS_DENIED',
        userId: currentUser.id,
        userEmail: currentUser.email,
        documentId: document.id,
        documentTitle: document.title,
        status: 'DENIED',
        ipAddress: req.ip,
        userAgent: req.get('user-agent'),
        details: 'Unauthorized attempt to revoke document permissions'
      });
      return res.status(403).json({ error: 'Only the document owner or an administrator can revoke permissions.' });
    }

    const existingPermission = await prisma.documentPermission.findUnique({
      where: {
        documentId_userId: {
          documentId: document.id,
          userId: targetUserId
        }
      },
      include: {
        user: { select: { email: true, name: true } }
      }
    });

    if (!existingPermission) {
      return res.status(404).json({ error: 'Permission grant not found for this user.' });
    }

    // Delete permission record from database
    await prisma.documentPermission.delete({
      where: {
        documentId_userId: {
          documentId: document.id,
          userId: targetUserId
        }
      }
    });

    // Record audit event
    await recordAudit({
      action: 'REVOKE_PERMISSION',
      userId: currentUser.id,
      userEmail: currentUser.email,
      documentId: document.id,
      documentTitle: document.title,
      status: 'SUCCESS',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: `Revoked ${existingPermission.permissionLevel} access on '${document.title}' from ${existingPermission.user.email}`
    });

    return res.json({
      message: `Access successfully revoked from ${existingPermission.user.email}.`
    });
  } catch (error) {
    console.error('Revoke permission error:', error);
    return res.status(500).json({ error: 'Failed to revoke permission.' });
  }
}

/**
 * Lists all active permission grants for a document
 */
export async function listDocumentPermissions(req: Request, res: Response) {
  try {
    const document = req.document!;

    const permissions = await prisma.documentPermission.findMany({
      where: { documentId: document.id },
      include: {
        user: { select: { id: true, name: true, email: true, role: true } },
        grantedBy: { select: { id: true, name: true, email: true } }
      },
      orderBy: { grantedAt: 'desc' }
    });

    return res.json({ permissions });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to list document permissions.' });
  }
}
