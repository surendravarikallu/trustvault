import React, { useState } from 'react';
import {
  Search,
  Download,
  Trash2,
  Users,
  Upload,
  Filter,
  X,
  FileText,
  Copy,
  Check,
  ShieldAlert,
  Lock,
  RefreshCw,
  Eye,
  Flame,
  Shield,
  ShieldCheck,
  FolderArchive,
  HardDrive,
  Edit3,
  History,
  CheckCircle2,
  Database
} from 'lucide-react';
import type { VaultDocument, User } from '../types';

interface DocumentListProps {
  documents: VaultDocument[];
  currentUser: User;
  onDownload: (doc: VaultDocument) => void;
  onOpenUpload: () => void;
  onOpenPermissions: (doc: VaultDocument) => void;
  onOpenRevision?: (doc: VaultDocument) => void;
  onOpenHistory?: (doc: VaultDocument) => void;
  onDeleteDocument: (docId: string) => void;
  onSearch: (filters: { q?: string; owner?: string; category?: string; fromDate?: string; toDate?: string }) => void;
  isLoading: boolean;
}

export const DocumentList: React.FC<DocumentListProps> = ({
  documents,
  currentUser,
  onDownload,
  onOpenUpload,
  onOpenPermissions,
  onOpenRevision,
  onOpenHistory,
  onDeleteDocument,
  onSearch,
  isLoading
}) => {
  const [q, setQ] = useState('');
  const [owner, setOwner] = useState('');
  const [category, setCategory] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Sub-navigation view filter state
  const [subFilter, setSubFilter] = useState<'all' | 'owned' | 'shared' | 'read' | 'edit' | 'burn'>('all');

  const handleApplyFilter = (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    onSearch({
      q: q || undefined,
      owner: owner || undefined,
      category: category || undefined,
      fromDate: fromDate || undefined,
      toDate: toDate || undefined
    });
  };

  const handleReset = () => {
    setQ('');
    setOwner('');
    setCategory('');
    setFromDate('');
    setToDate('');
    onSearch({});
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const formatSize = (bytes: number) => {
    if (!bytes || isNaN(bytes)) return '0 B';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const isOwnerUser = currentUser.role === 'OWNER';
  const isViewerUser = currentUser.role === 'VIEWER';
  const isAdminUser = currentUser.role === 'ADMIN';
  const canUpload = isOwnerUser || isAdminUser;

  // Segmentations for metrics and role-tailored views
  const ownedDocs = documents.filter((d) => d.owner?.id === currentUser.id || d.ownerId === currentUser.id);
  const sharedWithMeDocs = documents.filter((d) => d.owner?.id !== currentUser.id && d.ownerId !== currentUser.id);
  const ownedStorage = ownedDocs.reduce((acc, d) => acc + (d.fileSize || 0), 0);
  const totalSystemStorage = documents.reduce((acc, d) => acc + (d.fileSize || 0), 0);

  // Collaborations count: documents owned by me that have active permissions
  const activeCollaborations = ownedDocs.filter(
    (d) => Array.isArray(d.permissions) && d.permissions.length > 0
  ).length;

  // Viewer categorizations
  const readOnlyDocs = documents.filter((d) => {
    const grant = Array.isArray(d.permissions) && d.permissions.length > 0 ? d.permissions[0] : null;
    return !grant || grant.permissionLevel === 'READ' || grant.previewOnly;
  });

  const editDocs = documents.filter((d) => {
    const grant = Array.isArray(d.permissions) && d.permissions.length > 0 ? d.permissions[0] : null;
    return grant && grant.permissionLevel === 'EDIT' && !grant.previewOnly;
  });

  const burnOnDownloadDocs = documents.filter((d) => {
    const grant = Array.isArray(d.permissions) && d.permissions.length > 0 ? d.permissions[0] : null;
    return grant && grant.burnOnDownload;
  });

  // Apply Sub-filter
  const displayDocuments = documents.filter((d) => {
    if (subFilter === 'all') return true;
    if (subFilter === 'owned') return d.owner?.id === currentUser.id || d.ownerId === currentUser.id;
    if (subFilter === 'shared') return d.owner?.id !== currentUser.id && d.ownerId !== currentUser.id;
    if (subFilter === 'read') {
      const grant = Array.isArray(d.permissions) && d.permissions.length > 0 ? d.permissions[0] : null;
      return !grant || grant.permissionLevel === 'READ' || grant.previewOnly;
    }
    if (subFilter === 'edit') {
      const grant = Array.isArray(d.permissions) && d.permissions.length > 0 ? d.permissions[0] : null;
      return grant && grant.permissionLevel === 'EDIT' && !grant.previewOnly;
    }
    if (subFilter === 'burn') {
      const grant = Array.isArray(d.permissions) && d.permissions.length > 0 ? d.permissions[0] : null;
      return grant && grant.burnOnDownload;
    }
    return true;
  });

  return (
    <div>
      {/* ============================================================
          Role-Tailored KPI Metric Cards
          ============================================================ */}
      {isOwnerUser && (
        <div className="metrics-grid">
          <div className="metric-card">
            <div className="metric-label">Vault Documents Owned</div>
            <div className="metric-value">
              <FolderArchive size={20} color="#60a5fa" />
              <span>{ownedDocs.length}</span>
            </div>
            <div className="metric-meta">Cryptographic ownership & lifecycle control</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Active Shared Collaborations</div>
            <div className="metric-value">
              <Users size={20} color="var(--color-indigo)" />
              <span>{activeCollaborations} Files</span>
            </div>
            <div className="metric-meta">Selective READ / EDIT delegation</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Total Encrypted Storage</div>
            <div className="metric-value">
              <HardDrive size={20} color="var(--color-emerald)" />
              <span>{formatSize(ownedStorage)}</span>
            </div>
            <div className="metric-meta">AES-256-GCM envelope ciphertext</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Clearance & Authority</div>
            <div className="metric-value">
              <ShieldCheck size={20} color="var(--color-emerald)" />
              <span style={{ fontSize: '15px' }}>Document Owner</span>
            </div>
            <div className="metric-meta">Full Upload, Versioning & Delegation Authority</div>
          </div>
        </div>
      )}

      {isViewerUser && (
        <div className="metrics-grid">
          <div className="metric-card">
            <div className="metric-label">Accessible Documents</div>
            <div className="metric-value">
              <FileText size={20} color="#60a5fa" />
              <span>{documents.length}</span>
            </div>
            <div className="metric-meta">Zero-Trust Grant Scope Enforced</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Read-Only Clearance</div>
            <div className="metric-value">
              <Eye size={20} color="var(--color-emerald)" />
              <span>{readOnlyDocs.length} Files</span>
            </div>
            <div className="metric-meta">In-browser ephemeral streaming & download</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Collaborative Edit Rights</div>
            <div className="metric-value">
              <Edit3 size={20} color="var(--color-amber)" />
              <span>{editDocs.length} Files</span>
            </div>
            <div className="metric-meta">Authorized version revision & replacement</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Single-Use Transfers</div>
            <div className="metric-value">
              <Flame size={20} color="#fca5a5" />
              <span>{burnOnDownloadDocs.length} Ephemeral</span>
            </div>
            <div className="metric-meta">Grants auto-revoke upon download completion</div>
          </div>
        </div>
      )}

      {isAdminUser && (
        <div className="metrics-grid">
          <div className="metric-card">
            <div className="metric-label">Total Managed Documents</div>
            <div className="metric-value">
              <Database size={20} color="#60a5fa" />
              <span>{documents.length}</span>
            </div>
            <div className="metric-meta">Zero-Trust: Metadata & Audit oversight only</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Total Encrypted Volume</div>
            <div className="metric-value">
              <HardDrive size={20} color="var(--color-indigo)" />
              <span>{formatSize(totalSystemStorage)}</span>
            </div>
            <div className="metric-meta">Envelope-encrypted via master PBKDF2 key</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Cryptographic Ledger Link</div>
            <div className="metric-value">
              <ShieldCheck size={20} color="var(--color-emerald)" />
              <span style={{ fontSize: '15px' }}>HMAC-SHA256 Active</span>
            </div>
            <div className="metric-meta">Tamper-evident sequential audit log</div>
          </div>

          <div className="metric-card">
            <div className="metric-label">Administrative Boundary</div>
            <div className="metric-value">
              <Lock size={20} color="#fca5a5" />
              <span style={{ fontSize: '15px' }}>Access Restricted</span>
            </div>
            <div className="metric-meta">Direct content download requires owner grant</div>
          </div>
        </div>
      )}

      {/* ============================================================
          Control Toolbar, Sub-Filters & Actions
          ============================================================ */}
      <div className="toolbar-panel">
        <form onSubmit={handleApplyFilter} style={{ display: 'flex', gap: '8px', flex: 1, flexWrap: 'wrap' }}>
          <div className="search-input-group">
            <Search size={14} color="var(--text-dim)" />
            <input
              type="text"
              placeholder="Search documents by title, original filename, or metadata..."
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>

          <button type="submit" className="btn btn-secondary" disabled={isLoading}>
            {isLoading ? <RefreshCw size={13} className="spin-icon" /> : 'Filter'}
          </button>

          <button
            type="button"
            className={`btn ${showAdvanced ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            <Filter size={13} />
            <span>Advanced Filters</span>
          </button>

          {(q || owner || category || fromDate || toDate) && (
            <button type="button" className="btn btn-secondary" onClick={handleReset}>
              <X size={13} />
              <span>Clear</span>
            </button>
          )}
        </form>

        {canUpload ? (
          <button className="btn btn-primary" onClick={onOpenUpload}>
            <Upload size={14} />
            <span>Upload Secure Document</span>
          </button>
        ) : (
          <div
            style={{
              fontSize: '11px',
              color: 'var(--text-muted)',
              border: '1px solid var(--border-default)',
              padding: '6px 10px',
              borderRadius: 'var(--radius-sm)',
              background: 'var(--bg-surface)'
            }}
          >
            <Lock size={12} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
            Role <span className="mono-cell">{currentUser.role}</span>: Upload Rights Restricted
          </div>
        )}
      </div>

      {/* Role-Specific Sub-Navigation Tabs */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '8px',
          marginBottom: '16px',
          borderBottom: '1px solid var(--border-subtle)',
          paddingBottom: '8px',
          flexWrap: 'wrap'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', marginRight: '6px' }}>
            View Scope:
          </span>

          {isOwnerUser && (
            <>
              <button
                type="button"
                className={`btn btn-xs ${subFilter === 'all' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSubFilter('all')}
              >
                All Documents ({documents.length})
              </button>
              <button
                type="button"
                className={`btn btn-xs ${subFilter === 'owned' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSubFilter('owned')}
              >
                My Uploads ({ownedDocs.length})
              </button>
              <button
                type="button"
                className={`btn btn-xs ${subFilter === 'shared' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSubFilter('shared')}
              >
                Shared With Me ({sharedWithMeDocs.length})
              </button>
            </>
          )}

          {isViewerUser && (
            <>
              <button
                type="button"
                className={`btn btn-xs ${subFilter === 'all' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSubFilter('all')}
              >
                All Accessible ({documents.length})
              </button>
              <button
                type="button"
                className={`btn btn-xs ${subFilter === 'read' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSubFilter('read')}
              >
                Read-Only ({readOnlyDocs.length})
              </button>
              <button
                type="button"
                className={`btn btn-xs ${subFilter === 'edit' ? 'btn-primary' : 'btn-secondary'}`}
                onClick={() => setSubFilter('edit')}
              >
                Can Edit ({editDocs.length})
              </button>
              {burnOnDownloadDocs.length > 0 && (
                <button
                  type="button"
                  className={`btn btn-xs ${subFilter === 'burn' ? 'btn-primary' : 'btn-secondary'}`}
                  onClick={() => setSubFilter('burn')}
                >
                  Single-Use ({burnOnDownloadDocs.length})
                </button>
              )}
            </>
          )}

          {isAdminUser && (
            <button
              type="button"
              className="btn btn-xs btn-primary"
              onClick={() => setSubFilter('all')}
            >
              All Enterprise Managed Vaults ({documents.length})
            </button>
          )}
        </div>

        <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
          Showing {displayDocuments.length} of {documents.length} documents
        </div>
      </div>

      {/* Advanced Filter Expansion Panel */}
      {showAdvanced && (
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-default)',
            borderRadius: 'var(--radius-sm)',
            padding: '12px 16px',
            marginBottom: '16px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))',
            gap: '12px'
          }}
        >
          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontWeight: 600 }}>
              Owner
            </label>
            <input
              type="text"
              placeholder="e.g. Alice or owner@..."
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
            />
          </div>

          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontWeight: 600 }}>
              Category
            </label>
            <select value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">All Categories</option>
              <option value="Legal">Legal</option>
              <option value="Finance">Finance</option>
              <option value="HR">HR</option>
              <option value="Engineering">Engineering</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontWeight: 600 }}>
              From Date
            </label>
            <input type="date" value={fromDate} onChange={(e) => setFromDate(e.target.value)} />
          </div>

          <div>
            <label style={{ fontSize: '11px', color: 'var(--text-muted)', display: 'block', marginBottom: '4px', textTransform: 'uppercase', fontWeight: 600 }}>
              To Date
            </label>
            <input type="date" value={toDate} onChange={(e) => setToDate(e.target.value)} />
          </div>
        </div>
      )}

      {/* Zero Documents / Information Barrier State */}
      {displayDocuments.length === 0 ? (
        <div className="zero-trust-empty-card">
          <div className="zero-trust-empty-icon">
            {currentUser.email === 'eve@trustvault.local' ? <ShieldAlert size={22} /> : <Lock size={22} />}
          </div>
          <h4>
            {currentUser.email === 'eve@trustvault.local'
              ? '404 Information Barrier Active (Zero-Trust Enforced)'
              : 'No Documents Match Active View Scope'}
          </h4>
          <p>
            {currentUser.email === 'eve@trustvault.local'
              ? 'Principal eve@trustvault.local has zero explicit permissions. The DAL layer returns 404 (Not Found) rather than 403 to prevent metadata or existence leakage.'
              : subFilter !== 'all'
              ? `No documents found under the "${subFilter}" filter. Try switching to "All" or adjusting search parameters.`
              : 'No documents exist within your clearance scope matching the active search parameters.'}
          </p>
          {canUpload && (
            <button className="btn btn-primary" onClick={onOpenUpload}>
              <Upload size={14} />
              <span>Upload Your First Document</span>
            </button>
          )}
        </div>
      ) : (
        /* Enterprise Document Table */
        <div className="data-table-wrapper">
          <table className="data-table">
            <thead>
              <tr>
                <th>Document Name & File</th>
                <th>Category</th>
                <th>Owner</th>
                <th>Size</th>
                <th>Access Level</th>
                <th>SHA-256 Checksum</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {displayDocuments.map((doc) => {
                const isOwner = doc.owner?.id === currentUser.id || doc.ownerId === currentUser.id;
                const myGrant = Array.isArray(doc.permissions) && doc.permissions.length > 0 ? doc.permissions[0] : null;
                const hasGrant = !!myGrant;
                const isBurnOnDownload = !isOwner && !!myGrant?.burnOnDownload;
                const canDownload = isOwner || hasGrant;
                const canManage = isOwner; // L-03: Strict owner-only delegation
                const canEdit = isOwner || myGrant?.permissionLevel === 'EDIT';
                const hashValue = doc.fileHash || 'Verified-Blob';

                return (
                  <tr key={doc.id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                        <div
                          style={{
                            width: '28px',
                            height: '28px',
                            borderRadius: 'var(--radius-xs)',
                            background: 'var(--bg-surface-raised)',
                            border: '1px solid var(--border-default)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            color: 'var(--text-secondary)'
                          }}
                        >
                          <FileText size={15} />
                        </div>
                        <div style={{ minWidth: 0, maxWidth: '280px' }}>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={doc.title}>{doc.title}</span>
                            {isBurnOnDownload && (
                              <span
                                className="category-pill"
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '3px',
                                  borderColor: 'var(--color-rose-border)',
                                  color: '#fca5a5',
                                  background: 'var(--color-rose-subtle)',
                                  fontSize: '10px',
                                  flexShrink: 0
                                }}
                                title="Single-use transfer: Access grant closes immediately upon successful download"
                              >
                                <Flame size={10} />
                                <span>Burn-on-Download</span>
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={doc.originalFilename}>
                            {doc.originalFilename}
                          </div>
                        </div>
                      </div>
                    </td>

                    <td>
                      <span className="category-pill">{doc.category}</span>
                    </td>

                    <td>
                      <div style={{ fontSize: '12px' }}>{doc.owner?.name || 'Authorized Owner'}</div>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
                        {doc.owner?.email}
                      </div>
                    </td>

                    <td className="mono-cell">{formatSize(doc.fileSize)}</td>

                    {/* Accurate Role-Aware Access Level Badge */}
                    <td>
                      {isOwner ? (
                        <span className="status-pill status-SUCCESS" style={{ background: 'rgba(59, 130, 246, 0.15)', color: '#93c5fd', borderColor: 'rgba(59, 130, 246, 0.3)' }}>
                          <Shield size={10} style={{ marginRight: '4px' }} /> OWNER
                        </span>
                      ) : hasGrant && myGrant?.permissionLevel === 'EDIT' ? (
                        <span className="status-pill status-SUCCESS" style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#fbbf24', borderColor: 'rgba(245, 158, 11, 0.3)' }}>
                          <Edit3 size={10} style={{ marginRight: '4px' }} /> AUTHORIZED EDIT
                        </span>
                      ) : hasGrant ? (
                        <span className="status-pill status-SUCCESS" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#6ee7b7', borderColor: 'rgba(16, 185, 129, 0.3)' }}>
                          <CheckCircle2 size={10} style={{ marginRight: '4px' }} /> AUTHORIZED READ
                        </span>
                      ) : currentUser.role === 'ADMIN' ? (
                        <span className="status-pill status-FAILED" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5', borderColor: 'rgba(239, 68, 68, 0.25)' }}>
                          <Lock size={10} style={{ marginRight: '4px' }} /> ZERO-TRUST OVERSIGHT
                        </span>
                      ) : (
                        <span className="status-pill status-DENIED">RESTRICTED</span>
                      )}
                    </td>

                    <td>
                      <div className="hash-pill" title={hashValue}>
                        <span>{hashValue.substring(0, 10)}...</span>
                        <button
                          type="button"
                          onClick={() => copyToClipboard(hashValue, doc.id)}
                          style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'inherit', padding: '0 2px' }}
                          title="Copy Full SHA-256 Hash"
                        >
                          {copiedId === doc.id ? <Check size={11} color="var(--color-emerald)" /> : <Copy size={11} />}
                        </button>
                      </div>
                    </td>

                    {/* Operational Action Controls */}
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                        {canDownload ? (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onDownload(doc)}
                            title={isBurnOnDownload ? "Single-Use Transfer: Access grant will auto-revoke upon download completion" : "Stream in-memory decrypted blob (Logged to Audit Ledger)"}
                            style={isBurnOnDownload ? { borderColor: 'var(--color-rose-border)', color: '#fca5a5' } : {}}
                          >
                            <Download size={12} />
                            <span>Download</span>
                          </button>
                        ) : currentUser.role === 'ADMIN' ? (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onDownload(doc)}
                            title="Zero-Trust Enforced: Security Admins have oversight but cannot download private blobs without an explicit owner grant"
                            style={{ borderColor: 'rgba(239, 68, 68, 0.3)', color: '#fca5a5' }}
                          >
                            <Lock size={12} color="var(--color-rose)" />
                            <span>Admin Zero-Trust</span>
                          </button>
                        ) : (
                          <button
                            className="btn btn-secondary btn-sm"
                            disabled
                            style={{ opacity: 0.5, cursor: 'not-allowed' }}
                            title="Access Restricted"
                          >
                            <Lock size={12} />
                            <span>Restricted</span>
                          </button>
                        )}

                        {/* Revision button for Owners and Authorized Editors */}
                        {canEdit && onOpenRevision && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onOpenRevision(doc)}
                            title="Upload Replacement Revision / New Version (Preserves history in ledger)"
                            style={{ borderColor: 'rgba(245, 158, 11, 0.4)', color: '#fbbf24' }}
                          >
                            <RefreshCw size={12} />
                            <span>Revision</span>
                          </button>
                        )}

                        {/* Version History button for Document Owners */}
                        {isOwner && onOpenHistory && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onOpenHistory(doc)}
                            title="View Cryptographic Version History"
                          >
                            <History size={12} />
                            <span>History</span>
                          </button>
                        )}

                        {/* Access Control button for Document Owners */}
                        {canManage && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onOpenPermissions(doc)}
                            title="Manage Access Delegation & Policy Recommender"
                          >
                            <Users size={12} />
                            <span>Share</span>
                          </button>
                        )}

                        {/* Soft Delete button for Document Owners */}
                        {isOwner && (
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => onDeleteDocument(doc.id)}
                            title="Soft delete document"
                          >
                            <Trash2 size={12} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
