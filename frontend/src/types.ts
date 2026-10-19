export type Role = 'ADMIN' | 'OWNER' | 'VIEWER';
export type PermissionLevel = 'READ' | 'EDIT';
export type AuditStatus = 'SUCCESS' | 'DENIED' | 'FAILED';

export interface User {
  id: string;
  email: string;
  name: string;
  role: Role;
  isActive?: boolean;
  tokenVersion?: number;
}

export interface DocumentPermission {
  id: string;
  permissionLevel: PermissionLevel;
  expiresAt: string | null;
  userId?: string;
  user: {
    id: string;
    name: string;
    email: string;
    role: Role;
  };
  grantedBy: {
    id: string;
    name: string;
    email: string;
  };
  grantedAt: string;
}

export interface VaultDocument {
  id: string;
  title: string;
  description: string | null;
  originalFilename: string;
  fileSize: number;
  mimeType: string;
  category: string;
  fileHash?: string;
  ownerId?: string;
  createdAt: string;
  updatedAt: string;
  owner: {
    id: string;
    name: string;
    email: string;
  };
  permissions?: {
    permissionLevel: PermissionLevel;
    expiresAt: string | null;
  }[];
}

export interface AuditRecord {
  id: string;
  sequenceNumber: string;
  timestamp: string;
  action: string;
  userId: string | null;
  userEmail: string | null;
  userName?: string | null;
  documentId: string | null;
  documentTitle: string | null;
  status: AuditStatus;
  ipAddress: string;
  userAgent: string;
  details: string;
  previousHash: string;
  hash: string;
}

export interface AuditVerification {
  valid: boolean;
  totalRecords: number;
  headSequence?: string;
  headHash?: string;
  anchorMatched?: boolean;
  error?: string;
  compromisedSequence?: string;
}

export interface ReviewerSuggestion {
  userId: string;
  email: string;
  name: string;
  suggestedPermissionLevel: PermissionLevel;
  rationale: string;
}
