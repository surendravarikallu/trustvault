import { Response } from 'express';
import bcrypt from 'bcrypt';
import { z } from 'zod';
import { Role, AuditStatus } from '../dal/types';
import { AuthenticatedRequest } from '../middleware/auth';
import { getRequestContext } from './documentController';
import { listDocuments } from '../dal/documentDal';
import { getAuditLogs, verifyAuditChain, logAuditEvent } from '../dal/auditDal';
import {
  setUserRole,
  setUserActive,
  listAllUsers,
  getUserById,
  getUserByEmail,
  createUser,
  adminResetPassword,
  adminResetMfa
} from '../dal/userDal';
import { BackupService } from '../services/backupService';
import { RetentionService } from '../services/retentionService';

const RoleChangeSchema = z.object({
  role: z.nativeEnum(Role)
});

const CreateUserSchema = z.object({
  name: z.string().min(2, 'Name must be at least 2 characters'),
  email: z.string().email('Valid corporate email required'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  role: z.nativeEnum(Role).optional().default(Role.VIEWER)
});

const ResetPasswordSchema = z.object({
  newPassword: z.string().min(8, 'New password must be at least 8 characters')
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
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit as string, 10) || 100));

  try {
    const result = await listAllUsers(page, limit);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function createAdminUserHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const admin = req.user!;
  const parseResult = CreateUserSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { name, email, password, role } = parseResult.data;

  try {
    const existing = await getUserByEmail(email);
    if (existing) {
      res.status(400).json({ error: 'User with this email already exists.' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const newUser = await createUser({
      name,
      email,
      passwordHash,
      role
    });

    await logAuditEvent({
      action: 'USER_CREATED_BY_ADMIN',
      userId: admin.id,
      userEmail: admin.email,
      documentId: null,
      documentTitle: null,
      status: AuditStatus.SUCCESS,
      ipAddress: getRequestContext(req).ip,
      userAgent: getRequestContext(req).userAgent,
      details: `Admin ${admin.email} created user ${newUser.email} with role ${newUser.role}.`
    });

    res.status(201).json({
      message: `User ${newUser.email} created successfully.`,
      user: {
        id: newUser.id,
        name: newUser.name,
        email: newUser.email,
        role: newUser.role,
        isActive: newUser.isActive
      }
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function adminResetPasswordHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const admin = req.user!;
  const { id } = req.params;

  const parseResult = ResetPasswordSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { newPassword } = parseResult.data;

  try {
    const targetUser = await getUserById(id);
    if (!targetUser) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const passwordHash = await bcrypt.hash(newPassword, 12);
    const updated = await adminResetPassword(id, passwordHash);

    await logAuditEvent({
      action: 'USER_PASSWORD_RESET_BY_ADMIN',
      userId: admin.id,
      userEmail: admin.email,
      documentId: null,
      documentTitle: null,
      status: AuditStatus.SUCCESS,
      ipAddress: getRequestContext(req).ip,
      userAgent: getRequestContext(req).userAgent,
      details: `Admin ${admin.email} reset password for user ${targetUser.email}. All sessions terminated.`
    });

    res.json({
      message: `Password reset successfully for ${targetUser.email}. All active sessions invalidated.`,
      tokenVersion: updated.tokenVersion
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function adminResetMfaHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const admin = req.user!;
  const { id } = req.params;

  try {
    const targetUser = await getUserById(id);
    if (!targetUser) {
      res.status(404).json({ error: 'User not found.' });
      return;
    }

    const updated = await adminResetMfa(id);

    await logAuditEvent({
      action: 'USER_MFA_RESET_BY_ADMIN',
      userId: admin.id,
      userEmail: admin.email,
      documentId: null,
      documentTitle: null,
      status: AuditStatus.SUCCESS,
      ipAddress: getRequestContext(req).ip,
      userAgent: getRequestContext(req).userAgent,
      details: `Admin ${admin.email} revoked MFA for user ${targetUser.email}. All sessions terminated.`
    });

    res.json({
      message: `MFA reset successfully for ${targetUser.email}. User can now log in and re-enroll authenticators.`,
      tokenVersion: updated.tokenVersion
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function createBackupHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const admin = req.user!;
  try {
    const backup = await BackupService.createFullBackup(admin.email);
    res.status(201).json({
      message: 'Cryptographic backup successfully created and verified.',
      backupId: backup.backupId,
      manifest: backup.manifest
    });
  } catch (error: any) {
    res.status(500).json({ error: `Backup creation failed: ${error.message}` });
  }
}

export async function listBackupsHandler(_req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    const manifests = await BackupService.listBackups();
    res.json({ backups: manifests });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function verifyBackupHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const { backupPath, backupId } = req.body;
  const target = backupPath || backupId;
  if (!target || typeof target !== 'string') {
    res.status(400).json({ error: 'Valid backupPath or backupId is required.' });
    return;
  }

  try {
    const result = await BackupService.verifyBackupArchive(target);
    res.json(result);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

export async function runCryptoShredHandler(req: AuthenticatedRequest, res: Response): Promise<void> {
  const admin = req.user!;
  const { olderThanDays, documentId } = req.body;

  try {
    if (documentId) {
      const report = await RetentionService.shredDocumentImmediately(
        documentId,
        admin.email,
        getRequestContext(req)
      );
      if (!report) {
        res.status(404).json({ error: 'Document not found or already purged.' });
        return;
      }
      res.json({ message: 'NIST SP 800-88 cryptographic shredding completed.', report });
      return;
    }

    const days = typeof olderThanDays === 'number' ? olderThanDays : 0;
    const reports = await RetentionService.runRetentionCycle(days, admin.email);
    res.json({
      message: `Retention purge executed. Crypto-shredded ${reports.length} documents.`,
      reports
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
}

