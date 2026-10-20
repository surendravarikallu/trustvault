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

function getAuthHeader(token: string | null): Record<string, string> {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export interface LoginResponse {
  token?: string;
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

export async function apiLogin(usernameOrEmail: string, password: string, enrollMfa?: boolean): Promise<LoginResponse> {
  const cleanId = usernameOrEmail.trim();
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
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

export async function apiConfirmEnrollMfa(mfaEnrollToken: string, code: string): Promise<{ token: string; user: User; backupCodes: string[] }> {
  const res = await fetch('/api/auth/mfa/confirm-enroll', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfaEnrollToken, code })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA enrollment confirmation failed.');
  }
  return data;
}

export async function apiVerifyLoginMfa(mfaChallengeToken: string, code: string): Promise<{ token: string; user: User }> {
  const res = await fetch('/api/auth/mfa/verify-login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mfaChallengeToken, code })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA verification failed.');
  }
  return data;
}

export async function apiSetupMfa(token: string): Promise<{ secret: string; qrCode: string; otpauthUrl: string }> {
  const res = await fetch('/api/auth/mfa/setup', {
    method: 'POST',
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA setup failed.');
  }
  return data;
}

export async function apiVerifyMfaSetup(token: string, code: string): Promise<{ message: string; backupCodes: string[] }> {
  const res = await fetch('/api/auth/mfa/verify-setup', {
    method: 'POST',
    headers: {
      ...getAuthHeader(token),
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

export async function apiDisableMfa(token: string, password: string, code: string): Promise<void> {
  const res = await fetch('/api/auth/mfa/disable', {
    method: 'POST',
    headers: {
      ...getAuthHeader(token),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ password, code })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'MFA disable failed.');
  }
}

export async function apiRegister(email: string, password: string, name: string): Promise<{ token: string; user: User }> {
  const res = await fetch('/api/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, name })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Registration failed.');
  }
  return data;
}

export async function fetchDocuments(
  token: string,
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
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to fetch documents.');
  }
  return data.documents || [];
}

export async function uploadDocument(formData: FormData, token: string): Promise<VaultDocument> {
  const res = await fetch('/api/documents', {
    method: 'POST',
    headers: getAuthHeader(token),
    body: formData
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to upload document.');
  }
  return data.document;
}

/**
 * In-Memory Blob Downloader.
 * Defense against Loophole L-02: Zero token exposure in query strings.
 */
export async function downloadDocument(id: string, originalFilename: string, token: string): Promise<void> {
  const res = await fetch(`/api/documents/${id}/download`, {
    headers: getAuthHeader(token)
  });

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

export async function fetchDocumentBlobUrl(
  id: string,
  token: string,
  preview = false
): Promise<{ blobUrl: string; mimeType: string; arrayBuffer: ArrayBuffer }> {
  const url = preview ? `/api/documents/${id}/download?preview=true` : `/api/documents/${id}/download`;
  const res = await fetch(url, {
    headers: getAuthHeader(token)
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: 'Fetch failed' }));
    throw new Error(err.error || `Request failed with HTTP ${res.status}`);
  }

  const rawContentType = res.headers.get('content-type') || 'application/pdf';
  // Strip any charset or directives from content-type header
  const mimeType = rawContentType.split(';')[0].trim();
  const rawBlob = await res.blob();
  const arrayBuffer = await rawBlob.arrayBuffer();
  const typedBlob = new Blob([rawBlob], { type: mimeType });
  const blobUrl = window.URL.createObjectURL(typedBlob);

  return { blobUrl, mimeType, arrayBuffer };
}

export async function deleteDocument(id: string, token: string): Promise<void> {
  const res = await fetch(`/api/documents/${id}`, {
    method: 'DELETE',
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to delete document.');
  }
}

export async function fetchDocumentPermissions(docId: string, token: string): Promise<DocumentPermission[]> {
  const res = await fetch(`/api/documents/${docId}/permissions`, {
    headers: getAuthHeader(token)
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
  token: string,
  options?: { burnOnDownload?: boolean; previewOnly?: boolean }
): Promise<void> {
  const res = await fetch(`/api/documents/${docId}/permissions`, {
    method: 'POST',
    headers: {
      ...getAuthHeader(token),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      targetEmail,
      permissionLevel,
      expiresAt,
      burnOnDownload: options?.burnOnDownload ?? false,
      previewOnly: options?.previewOnly ?? false
    })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to grant permission.');
  }
}

export async function revokePermission(docId: string, targetUserId: string, token: string): Promise<void> {
  const res = await fetch(`/api/documents/${docId}/permissions/${targetUserId}`, {
    method: 'DELETE',
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to revoke permission.');
  }
}

export async function suggestReviewersWithAI(docId: string, token: string): Promise<ReviewerSuggestion[]> {
  const res = await fetch(`/api/documents/${docId}/ai-share-suggest`, {
    method: 'POST',
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to get AI suggestions.');
  }
  return data.suggestions || [];
}

export async function fetchAuditLogs(
  token: string,
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
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to fetch audit logs.');
  }
  return data;
}

export async function verifyAuditLedger(token: string): Promise<AuditVerification> {
  const res = await fetch('/api/admin/audit-verify', {
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to verify ledger.');
  }
  return data;
}

export async function fetchAllUsers(token: string): Promise<{ total: number; users: User[] }> {
  const res = await fetch('/api/admin/users', {
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to fetch users.');
  }
  return data;
}

export async function changeUserRole(userId: string, role: Role, token: string): Promise<void> {
  const res = await fetch(`/api/admin/users/${userId}/role`, {
    method: 'PATCH',
    headers: {
      ...getAuthHeader(token),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ role })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to change role.');
  }
}

export async function deactivateUser(userId: string, token: string): Promise<void> {
  const res = await fetch(`/api/admin/users/${userId}/deactivate`, {
    method: 'POST',
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to deactivate user.');
  }
}

export async function apiAdminCreateUser(
  token: string,
  payload: { name: string; email: string; password: string; role: Role }
): Promise<{ message: string; user: User }> {
  const res = await fetch('/api/admin/users', {
    method: 'POST',
    headers: {
      ...getAuthHeader(token),
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
  token: string,
  userId: string,
  newPassword: string
): Promise<{ message: string }> {
  const res = await fetch(`/api/admin/users/${userId}/reset-password`, {
    method: 'POST',
    headers: {
      ...getAuthHeader(token),
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
  token: string,
  userId: string
): Promise<{ message: string }> {
  const res = await fetch(`/api/admin/users/${userId}/reset-2fa`, {
    method: 'POST',
    headers: getAuthHeader(token)
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Failed to reset 2FA.');
  }
  return data;
}
