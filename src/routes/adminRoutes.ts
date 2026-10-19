import { Router } from 'express';
import { Role } from '../dal/types';
import { authenticate, requireRole } from '../middleware/auth';
import {
  getAdminDocuments,
  getAuditTrail,
  verifyAuditLedger,
  changeUserRole,
  deactivateUser,
  getUsers
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
