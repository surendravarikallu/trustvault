import { Request, Response } from 'express';
import { PrismaClient } from '@prisma/client';
import { verifyAuditChainIntegrity } from '../services/auditService.js';

const prisma = new PrismaClient();

/**
 * Retrieves paginated audit trail logs for security analysis
 */
export async function getAuditLogs(req: Request, res: Response) {
  try {
    const page = Math.max(1, parseInt(req.query.page as string || '1', 10));
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string || '50', 10)));
    const skip = (page - 1) * limit;

    const { action, status, userId, documentId } = req.query;

    const where: any = {};
    if (action && typeof action === 'string') where.action = action;
    if (status && typeof status === 'string') where.status = status;
    if (userId && typeof userId === 'string') where.userId = userId;
    if (documentId && typeof documentId === 'string') where.documentId = documentId;

    const [logs, total] = await Promise.all([
      prisma.auditLog.findMany({
        where,
        orderBy: { sequenceNumber: 'desc' },
        skip,
        take: limit,
        include: {
          user: { select: { id: true, name: true, email: true, role: true } },
          document: { select: { id: true, title: true } }
        }
      }),
      prisma.auditLog.count({ where })
    ]);

    return res.json({
      logs,
      pagination: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get audit logs error:', error);
    return res.status(500).json({ error: 'Failed to fetch audit logs.' });
  }
}

/**
 * Verifies the SHA-256 cryptographic hash chain across the entire audit database
 * Proves that no records were deleted, inserted, or modified
 */
export async function verifyAuditLedger(req: Request, res: Response) {
  try {
    const result = await verifyAuditChainIntegrity();
    return res.json(result);
  } catch (error) {
    console.error('Audit verification error:', error);
    return res.status(500).json({ error: 'Audit chain verification failed.' });
  }
}

/**
 * Administrative security telemetry and system overview
 */
export async function getSecurityMetrics(req: Request, res: Response) {
  try {
    const [totalUsers, totalDocuments, totalAudits, deniedAttempts] = await Promise.all([
      prisma.user.count(),
      prisma.document.count(),
      prisma.auditLog.count(),
      prisma.auditLog.count({ where: { status: 'DENIED' } })
    ]);

    // Count recent activity (last 24 hours)
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const recentDenied = await prisma.auditLog.count({
      where: {
        status: 'DENIED',
        timestamp: { gte: yesterday }
      }
    });

    // Breakdown of audit logs by action
    const actionsGrouped = await prisma.auditLog.groupBy({
      by: ['action'],
      _count: { action: true }
    });

    return res.json({
      metrics: {
        totalUsers,
        totalDocuments,
        totalAudits,
        deniedAttempts,
        recentDenied24h: recentDenied,
        actionBreakdown: actionsGrouped.map(item => ({
          action: item.action,
          count: item._count.action
        }))
      }
    });
  } catch (error) {
    console.error('Metrics error:', error);
    return res.status(500).json({ error: 'Failed to retrieve metrics.' });
  }
}
