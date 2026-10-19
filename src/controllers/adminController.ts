import { Response } from 'express';
import { z } from 'zod';
import { Role, AuditStatus } from '../dal/types';
import { AuthenticatedRequest } from '../middleware/auth';
import { getRequestContext } from './documentController';
import { listDocuments } from '../dal/documentDal';
import { getAuditLogs, verifyAuditChain, logAuditEvent } from '../dal/auditDal';
import { setUserRole, setUserActive, listAllUsers, getUserById } from '../dal/userDal';

const RoleChangeSchema = z.object({
  role: z.nativeEnum(Role)
});

export async function getAdminDocuments(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string, 10) || 20));

  try {
    const result = await listDocuments(user, page, limit);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function getAuditTrail(req: AuthenticatedRequest, res: Response): Promise<void> {
  const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string, 10) || 50));
  const { action, documentId, userId } = req.query;

  try {
    const result = await getAuditLogs(
      {
        action: typeof action === 'string' ? action : undefined,
        documentId: typeof documentId === 'string' ? documentId : undefined,
        userId: typeof userId === 'string' ? userId : undefined
      },
      page,
      limit
    );
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function verifyAuditLedger(_req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const verification = await verifyAuditChain();
    res.json(verification);
  } catch (error: any) {
    res.status(500).json({ error: `Verification failed: ${error.message}` });
  }
}

export async function changeUserRole(req: AuthenticatedRequest, res: Response): Promise<void> {
  const admin = req.user!;
  const { id } = req.params;

  const parseResult = RoleChangeSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: 'Valid role (ADMIN, OWNER, VIEWER) is required.' });
    return;
  }

  const { role } = parseResult.data;

  try {
    const targetUser = await getUserById(id);
    if (!targetUser) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const previousRole = targetUser.role;
    const updated = await setUserRole(id, role);

    // Audit role change (Loophole L-01: Instant session revocation via tokenVersion increment)
    await logAuditEvent({
      action: 'USER_ROLE_CHANGED',
      userId: admin.id,
      userEmail: admin.email,
      documentId: null,
      documentTitle: null,
      status: AuditStatus.SUCCESS,
      ipAddress: getRequestContext(req).ip,
      userAgent: getRequestContext(req).userAgent,
      details: `Changed role of user ${targetUser.email} from ${previousRole} to ${role}. Token version bumped to ${updated.tokenVersion}.`
    });

    res.json({
      message: `User role updated to ${role}. All existing tokens for this user were invalidated immediately.`,
      user: {
        id: updated.id,
        email: updated.email,
        name: updated.name,
        role: updated.role,
        tokenVersion: updated.tokenVersion
      }
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function deactivateUser(req: AuthenticatedRequest, res: Response): Promise<void> {
  const admin = req.user!;
  const { id } = req.params;

  try {
    const targetUser = await getUserById(id);
    if (!targetUser) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    if (targetUser.id === admin.id) {
      res.status(400).json({ error: 'Administrators cannot deactivate their own account.' });
      return;
    }

    const updated = await setUserActive(id, false);

    await logAuditEvent({
      action: 'USER_DEACTIVATED',
      userId: admin.id,
      userEmail: admin.email,
      documentId: null,
      documentTitle: null,
      status: AuditStatus.SUCCESS,
      ipAddress: getRequestContext(req).ip,
      userAgent: getRequestContext(req).userAgent,
      details: `Deactivated user account ${targetUser.email}. Token version bumped to ${updated.tokenVersion}.`
    });

    res.json({ message: 'User deactivated. All active sessions invalidated immediately.' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function getUsers(req: AuthenticatedRequest, res: Response): Promise<void> {
  const page = Math.max(1, parseInt(req.query.page as string, 10) || 1);
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string, 10) || 50));

  try {
    const result = await listAllUsers(page, limit);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}
