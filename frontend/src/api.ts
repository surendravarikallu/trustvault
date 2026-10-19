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

export async function apiLogin(email: string, password: string): Promise<{ token: string; user: User }> {
  const res = await fetch('/api/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });

  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || 'Login failed.');
  }
  return data;
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
  token: string
): Promise<void> {
  const res = await fetch(`/api/documents/${docId}/permissions`, {
    method: 'POST',
    headers: {
      ...getAuthHeader(token),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ targetEmail, permissionLevel, expiresAt })
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
