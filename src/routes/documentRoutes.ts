import { Router } from 'express';
import multer from 'multer';
import { config } from '../config.js';
import { authenticateToken } from '../middleware/auth.js';
import { authorizeDocumentAccess } from '../middleware/permissions.js';
import {
  uploadDocument,
  listDocuments,
  getDocument,
  downloadDocument,
  deleteDocument
} from '../controllers/documentController.js';
import {
  grantPermission,
  revokePermission,
  listDocumentPermissions
} from '../controllers/permissionController.js';

const router = Router();

// Configure Multer with in-memory buffer to allow strict magic bytes inspection before disk write
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.maxFileSize
  }
});

// Document endpoints
router.post('/', authenticateToken, upload.single('file'), uploadDocument);
router.get('/', authenticateToken, listDocuments);
router.get('/:id', authenticateToken, authorizeDocumentAccess('read'), getDocument);
router.get('/:id/download', authenticateToken, authorizeDocumentAccess('read'), downloadDocument);
router.delete('/:id', authenticateToken, authorizeDocumentAccess('manage'), deleteDocument);

// Permission endpoints
router.post('/:id/permissions', authenticateToken, authorizeDocumentAccess('manage'), grantPermission);
router.delete('/:id/permissions/:userId', authenticateToken, authorizeDocumentAccess('manage'), revokePermission);
router.get('/:id/permissions', authenticateToken, authorizeDocumentAccess('read'), listDocumentPermissions);

export default router;
