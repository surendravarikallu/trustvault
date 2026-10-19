import { Role, PermissionLevel, AuditStatus } from '@prisma/client';

export { Role, PermissionLevel, AuditStatus };

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
