import type {
  User,
  VaultDocument,
  DocumentPermission,
  AuditRecord,
  AuditVerification,
  ReviewerSuggestion,
  Role,
  PermissionLevel
} from './types';

const CLIENT_HEADERS: Record<string, string> = {
  'X-TrustVault-Client': '1'
};

export interface LoginResponse {
  user?: User;
  mfaRequired?: boolean;
  mfaChallengeToken?: string;
  mfaEnrollRequired?: boolean;
  mfaEnrollToken?: string;
  qrCode?: string;
  secret?: string;
  otpauthUrl?: string;
  message?: string;
}

export async function apiMe(): Promise<{ user: User }> {
  const res = await fetch('/api/auth/me', {
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Session inactive.');
  }
  return data;
}

export async function apiLogin(usernameOrEmail: string, password: string, enrollMfa?: boolean): Promise<LoginResponse> {
  const cleanId = usernameOrEmail.trim();
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      email: cleanId,
      username: cleanId,
      password,
      enrollMfa
    })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Login failed.');
  }
  return data;
}

export async function apiLogout(): Promise<void> {
  await fetch('/api/auth/logout', {
    method: 'POST',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });
}

export async function apiConfirmEnrollMfa(mfaEnrollToken: string, code: string): Promise<{ user: User; backupCodes: string[] }> {
  const res = await fetch('/api/auth/mfa/confirm-enroll', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ mfaEnrollToken, code })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA enrollment confirmation failed.');
  }
  return data;
}

export async function apiVerifyLoginMfa(mfaChallengeToken: string, code: string): Promise<{ user: User }> {
  const res = await fetch('/api/auth/mfa/verify-login', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ mfaChallengeToken, code })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA verification failed.');
  }
  return data;
}

export async function apiSetupMfa(): Promise<{ secret: string; qrCode: string; otpauthUrl: string }> {
  const res = await fetch('/api/auth/mfa/setup', {
    method: 'POST',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA setup failed.');
  }
  return data;
}

export async function apiVerifyMfaSetup(code: string): Promise<{ message: string; backupCodes: string[] }> {
  const res = await fetch('/api/auth/mfa/verify-setup', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ code })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA confirmation failed.');
  }
  return data;
}

export async function apiDisableMfa(password: string, code: string): Promise<void> {
  const res = await fetch('/api/auth/mfa/disable', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ password, code })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA disable failed.');
  }
}

export async function apiRegister(email: string, password: string, name: string): Promise<{ user: User }> {
  const res = await fetch('/api/auth/register', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email, password, name })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Registration failed.');
  }
  return data;
}

export async function fetchDocuments(
  search?: { q?: string; owner?: string; category?: string; fromDate?: string; toDate?: string }
): Promise<VaultDocument[]> {
  let url = '/api/documents';
  if (search && Object.values(search).some((v) => !!v)) {
    const params = new URLSearchParams();
    if (search.q) params.set('q', search.q);
    if (search.owner) params.set('owner', search.owner);
    if (search.category) params.set('category', search.category);
    if (search.fromDate) params.set('fromDate', search.fromDate);
    if (search.toDate) params.set('toDate', search.toDate);
    url = `/api/documents/search?${params.toString()}`;
  }

  const res = await fetch(url, {
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to fetch documents.');
  }
  return data.documents || [];
}

export async function uploadDocument(formData: FormData): Promise<VaultDocument> {
  const res = await fetch('/api/documents', {
    method: 'POST',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS,
    body: formData
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to upload document.');
  }
  return data.document;
}

/**
 * In-Memory Safe Blob Downloader.
 * Authenticated strictly via __Host- HttpOnly cookie.
 */
export async function downloadDocument(id: string, originalFilename: string, otp?: string): Promise<void> {
  const headers: Record<string, string> = { ...CLIENT_HEADERS };
  if (otp) {
    headers['x-pdf-otp'] = otp;
  }

  const res = await fetch(`/api/documents/${id}/download`, {
    credentials: 'same-origin',
    headers
  });

  if (res.status === 401) {
    const err = await res.json().catch(() => ({}));
    if (err.pdfProtected && !otp) {
      const userOtp = window.prompt('🔒 This PDF is protected by an access policy.\nPlease enter the One-Time Password (OTP) to download and decrypt:');
      if (userOtp && userOtp.trim()) {
        return downloadDocument(id, originalFilename, userOtp.trim());
      }
      return;
    }
    throw new Error(err.error || 'Authentication required.');
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Download failed' }));
    throw new Error(err.error || `Download failed with HTTP ${res.status}`);
  }

  const blob = await res.blob();
  const blobUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = blobUrl;
  anchor.download = originalFilename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  window.URL.revokeObjectURL(blobUrl);
}

export async function deleteDocument(id: string): Promise<void> {
  const res = await fetch(`/api/documents/${id}`, {
    method: 'DELETE',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to delete document.');
  }
}

export async function replaceDocument(id: string, file: File): Promise<VaultDocument> {
  const formData = new FormData();
  formData.append('file', file);
  const res = await fetch(`/api/documents/${id}`, {
    method: 'PUT',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS,
    body: formData
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to replace document version.');
  }
  return data.document;
}

export interface DocumentVersionInfo {
  id: string;
  versionNumber: number;
  originalFilename: string;
  fileSize: number;
  mimeType: string;
  fileHash: string;
  createdAt: string;
  createdBy?: {
    id: string;
    name: string;
    email: string;
  };
}

export async function fetchDocumentVersions(id: string): Promise<DocumentVersionInfo[]> {
  const res = await fetch(`/api/documents/${id}/versions`, {
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to fetch version history.');
  }
  return data.versions || [];
}

export async function fetchDocumentPermissions(docId: string): Promise<DocumentPermission[]> {
  const res = await fetch(`/api/documents/${docId}/permissions`, {
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to fetch permissions.');
  }
  return data.grantees || [];
}

export async function grantPermission(
  docId: string,
  targetEmail: string,
  permissionLevel: PermissionLevel,
  expiresAt: string | null,
  options?: {
    burnOnDownload?: boolean;
    maxDownloads?: number;
    pdfProtected?: boolean;
    otp?: string;
    watermarkText?: string;
  }
): Promise<{ otp?: string }> {
  const res = await fetch(`/api/documents/${docId}/permissions`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      targetEmail,
      permissionLevel,
      expiresAt,
      burnOnDownload: options?.burnOnDownload ?? false,
      maxDownloads: options?.maxDownloads ?? (options?.burnOnDownload ? 1 : 0),
      pdfProtected: options?.pdfProtected ?? false,
      otp: options?.otp,
      watermarkText: options?.watermarkText
    })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to grant permission.');
  }
  return { otp: data.otp };
}

export async function revokePermission(docId: string, targetUserId: string): Promise<void> {
  const res = await fetch(`/api/documents/${docId}/permissions/${targetUserId}`, {
    method: 'DELETE',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to revoke permission.');
  }
}

export async function suggestReviewersWithAI(docId: string): Promise<ReviewerSuggestion[]> {
  const res = await fetch(`/api/documents/${docId}/ai-share-suggest`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to get AI suggestions.');
  }
  return data.suggestions || [];
}

export async function fetchAuditLogs(
  filter?: { action?: string; documentId?: string }
): Promise<{ total: number; logs: AuditRecord[] }> {
  let url = '/api/admin/audit-logs';
  if (filter && (filter.action || filter.documentId)) {
    const params = new URLSearchParams();
    if (filter.action) params.set('action', filter.action);
    if (filter.documentId) params.set('documentId', filter.documentId);
    url = `/api/admin/audit-logs?${params.toString()}`;
  }

  const res = await fetch(url, {
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to fetch audit logs.');
  }
  return data.logs ? { total: data.total, logs: data.logs } : { total: 0, logs: [] };
}

export async function verifyAuditLedger(): Promise<AuditVerification> {
  const res = await fetch('/api/admin/audit-verify', {
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to verify ledger.');
  }
  return data;
}

export async function fetchAllUsers(): Promise<{ total: number; users: User[] }> {
  const res = await fetch('/api/admin/users', {
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to fetch users.');
  }
  return data;
}

export async function changeUserRole(userId: string, role: Role): Promise<void> {
  const res = await fetch(`/api/admin/users/${userId}/role`, {
    method: 'PATCH',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ role })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to change role.');
  }
}

export async function deactivateUser(userId: string): Promise<void> {
  const res = await fetch(`/api/admin/users/${userId}/deactivate`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to deactivate user.');
  }
}

export async function apiAdminCreateUser(
  payload: { name: string; email: string; password: string; role: Role }
): Promise<{ message: string; user: User }> {
  const res = await fetch('/api/admin/users', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to create user.');
  }
  return data;
}

export async function apiAdminResetPassword(
  userId: string,
  newPassword: string
): Promise<{ message: string }> {
  const res = await fetch(`/api/admin/users/${userId}/reset-password`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      ...CLIENT_HEADERS,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ newPassword })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to reset password.');
  }
  return data;
}

export async function apiAdminResetMfa(
  userId: string
): Promise<{ message: string }> {
  const res = await fetch(`/api/admin/users/${userId}/reset-2fa`, {
    method: 'POST',
    credentials: 'same-origin',
    headers: CLIENT_HEADERS
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to reset 2FA.');
  }
  return data;
}
