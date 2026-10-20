import { Role, PermissionLevel, AuditStatus, User as DbUser } from '@prisma/client';

export { Role, PermissionLevel, AuditStatus, DbUser };

export interface UserContext {
  id: string;
  email: string;
  name: string;
  role: Role;
}

export interface RequestContext {
  ip: string;
  userAgent: string;
  details?: string;
}

export interface ActiveGrantContext {
  id: string;
  documentId: string;
  userId: string;
  permissionLevel: PermissionLevel;
  expiresAt: Date | null;
  burnOnDownload?: boolean;
  previewOnly?: boolean;
  downloadCount?: number;
  grantedById: string;
  grantedAt: Date;
}
