import { Router } from 'express';
import { authenticateToken, requireRole } from '../middleware/auth.js';
import { getAuditLogs, verifyAuditLedger, getSecurityMetrics } from '../controllers/adminController.js';

const router = Router();

// All admin routes strictly require authentication and ADMIN role
router.use(authenticateToken, requireRole('ADMIN'));

router.get('/audit-logs', getAuditLogs);
router.get('/audit-verify', verifyAuditLedger);
router.get('/metrics', getSecurityMetrics);

export default router;
