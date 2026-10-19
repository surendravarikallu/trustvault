import { Router } from 'express';
import { Role } from '../dal/types';
import { authenticate, requireRole } from '../middleware/auth';
import {
  getAdminDocuments,
  getAuditTrail,
  verifyAuditLedger,
  changeUserRole,
  deactivateUser,
  getUsers,
  createBackupHandler,
  listBackupsHandler,
  verifyBackupHandler,
  runCryptoShredHandler
} from '../controllers/adminController';

export const adminRouter = Router();

// Strictly locked to ADMIN role
adminRouter.use(authenticate, requireRole([Role.ADMIN]));

adminRouter.get('/documents', getAdminDocuments);
adminRouter.get('/audit-logs', getAuditTrail);
adminRouter.get('/audit/logs', getAuditTrail);
adminRouter.get('/audit-verify', verifyAuditLedger);
adminRouter.get('/audit/verify', verifyAuditLedger);
adminRouter.patch('/users/:id/role', changeUserRole);
adminRouter.post('/users/:id/deactivate', deactivateUser);
adminRouter.get('/users', getUsers);

// Disaster Recovery & Automated Backups
adminRouter.post('/backups', createBackupHandler);
adminRouter.get('/backups', listBackupsHandler);
adminRouter.post('/backups/verify', verifyBackupHandler);

// Retention Schedule & Crypto-Shredding (NIST SP 800-88)
adminRouter.post('/retention/crypto-shred', runCryptoShredHandler);

