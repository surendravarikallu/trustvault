import { Response } from 'express';
import { z } from 'zod';
import { PermissionLevel, AuditStatus } from '../dal/types';
import { AuthenticatedRequest } from '../middleware/auth';
import { getRequestContext } from './documentController';
import { loadDocumentFor, NotFoundError, ForbiddenError } from '../dal/documentDal';
import {
  grantDocumentPermission,
  revokeDocumentPermission,
  getGranteesForDocument
} from '../dal/permissionDal';
import { getUserByEmail, getEligibleReviewers } from '../dal/userDal';
import { logAuditEvent } from '../dal/auditDal';

const GrantPermissionSchema = z.object({
  targetEmail: z.string().email(),
  permissionLevel: z.nativeEnum(PermissionLevel),
  expiresAt: z.string().optional().nullable(),
  burnOnDownload: z.boolean().optional(),
  previewOnly: z.boolean().optional()
});

export async function grantPermission(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id } = req.params;

  const parseResult = GrantPermissionSchema.safeParse(req.body);
  if (!parseResult.success) {
    res.status(400).json({ error: parseResult.error.errors[0].message });
    return;
  }

  const { targetEmail, permissionLevel, expiresAt, burnOnDownload, previewOnly } = parseResult.data;

  try {
    // 1. Authorization check: Owner-only authority (L-03)
    await loadDocumentFor(user, id, 'manage_permissions', getRequestContext(req));

    // 2. Find target user
    const targetUser = await getUserByEmail(targetEmail);
    if (!targetUser || !targetUser.isActive) {
      res.status(404).json({ error: 'Target user does not exist or is inactive.' });
      return;
    }

    if (targetUser.id === user.id) {
      res.status(400).json({ error: 'Cannot grant permissions to yourself as the document owner.' });
      return;
    }

    const expirationDate = expiresAt ? new Date(expiresAt) : null;
    const grant = await grantDocumentPermission(
      id,
      targetUser.id,
      permissionLevel,
      expirationDate,
      user,
      getRequestContext(req),
      { burnOnDownload, previewOnly }
    );

    res.status(201).json({
      message: `Granted ${permissionLevel} permission to ${targetUser.email}.`,
      permission: grant
    });
  } catch (error: any) {
    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
}

export async function revokePermission(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id, userId } = req.params;

  try {
    // 1. Owner-only authorization (L-03)
    await loadDocumentFor(user, id, 'manage_permissions', getRequestContext(req));

    const revoked = await revokeDocumentPermission(id, userId, user, getRequestContext(req));
    if (!revoked) {
      res.status(404).json({ error: 'No active grant exists for this user on the document.' });
      return;
    }

    res.json({ message: 'Permission revoked immediately. Subsequent access will be blocked.' });
  } catch (error: any) {
    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
}

export async function listGrantees(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id } = req.params;

  try {
    // Verify visibility: Owner or Admin
    await loadDocumentFor(user, id, 'read', getRequestContext(req));

    const grantees = await getGranteesForDocument(id);
    res.json({ grantees });
  } catch (error: any) {
    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
}

/**
 * AI-Assisted Reviewer Suggestion Feature.
 * Invariant: The AI suggests candidate users; the human owner confirms; both are audited.
 */
export async function suggestReviewersWithAI(req: AuthenticatedRequest, res: Response): Promise<void> {
  const user = req.user!;
  const { id } = req.params;

  try {
    // 1. Owner-only authorization
    const { document } = await loadDocumentFor(user, id, 'manage_permissions', getRequestContext(req));

    // 2. Fetch candidate colleagues
    const candidates = await getEligibleReviewers(user.id);

    // 3. Heuristic / Category-based recommendation logic
    const suggestions = candidates.map((candidate) => {
      let suggestedLevel: PermissionLevel = PermissionLevel.READ;
      let rationale = `Eligible collaborator for ${document.category} documents.`;

      if (document.category.toLowerCase().includes('legal') && candidate.name.toLowerCase().includes('counsel')) {
        suggestedLevel = PermissionLevel.EDIT;
        rationale = 'Recommended for legal review and drafting.';
      } else if (document.category.toLowerCase().includes('finance')) {
        rationale = 'Recommended for finance verification audit.';
      }

      return {
        userId: candidate.id,
        email: candidate.email,
        name: candidate.name,
        suggestedPermissionLevel: suggestedLevel,
        rationale
      };
    });

    // 4. Record audit event for suggestion generation
    await logAuditEvent({
      action: 'AI_PERMISSION_SUGGESTION_GENERATED',
      userId: user.id,
      userEmail: user.email,
      documentId: document.id,
      documentTitle: document.title,
      status: AuditStatus.SUCCESS,
      ipAddress: getRequestContext(req).ip,
      userAgent: getRequestContext(req).userAgent,
      details: `Generated ${suggestions.length} reviewer suggestions for ${document.title}`
    });

    res.json({
      documentId: document.id,
      documentTitle: document.title,
      suggestions
    });
  } catch (error: any) {
    if (error instanceof NotFoundError) {
      res.status(404).json({ error: 'Document not found.' });
    } else if (error instanceof ForbiddenError) {
      res.status(403).json({ error: error.message });
    } else {
      res.status(500).json({ error: error.message });
    }
  }
}
