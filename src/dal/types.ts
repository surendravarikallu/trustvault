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
