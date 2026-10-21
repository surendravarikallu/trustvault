import { Router, Response, NextFunction } from 'express';
import { authenticate, AuthenticatedRequest } from '../middleware/auth';
import { Role } from '../dal/types';
import { multerUpload, validateUploadedFile } from '../middleware/uploadValidator';
import {
  uploadDocument,
  getDocuments,
  searchDocs,
  getDocumentById,
  downloadDocument,
  replaceDocumentFile,
  deleteDocument,
  getVersions
} from '../controllers/documentController';
import {
  grantPermission,
  revokePermission,
  listGrantees,
  suggestReviewersWithAI
} from '../controllers/permissionController';

export const documentRouter = Router();

// All document routes require active authenticated session
documentRouter.use(authenticate);

// Defense against Loophole L-05: Restrict VIEWERs before file buffer/temp processing
function requireUploaderRole(req: AuthenticatedRequest, res: Response, next: any): void {
  if (req.user?.role === Role.VIEWER) {
    res.status(403).json({ error: 'Viewers cannot upload documents. Owner promotion required.' });
    return;
  }
  next();
}

// Document CRUD & Search
documentRouter.post('/', requireUploaderRole, multerUpload.single('file'), validateUploadedFile, uploadDocument);
documentRouter.get('/', getDocuments);
documentRouter.get('/search', searchDocs);
documentRouter.get('/:id', getDocumentById);
documentRouter.get('/:id/download', downloadDocument);
documentRouter.put('/:id', multerUpload.single('file'), validateUploadedFile, replaceDocumentFile);
documentRouter.delete('/:id', deleteDocument);

// Version history (Owner-only)
documentRouter.get('/:id/versions', getVersions);

// Permissions management (Owner-only)
documentRouter.post('/:id/permissions', grantPermission);
documentRouter.delete('/:id/permissions/:userId', revokePermission);
documentRouter.get('/:id/permissions', listGrantees);

// AI reviewer suggestion helper (Owner-only)
documentRouter.post('/:id/ai-share-suggest', suggestReviewersWithAI);
