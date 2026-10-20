import React, { useState } from 'react';
import { Search, Download, Trash2, Users, Upload, Filter, X, FileText, Copy, Check, ShieldAlert, Lock, RefreshCw, Eye, Flame } from 'lucide-react';
import type { VaultDocument, User } from '../types';

interface DocumentListProps {
  documents: VaultDocument[];
  currentUser: User;
  onDownload: (doc: VaultDocument) => void;
  onPreview: (doc: VaultDocument) => void;
  onOpenUpload: () => void;
  onOpenPermissions: (doc: VaultDocument) => void;
  onDeleteDocument: (docId: string) => void;
  onSearch: (filters: { q?: string; owner?: string; category?: string; fromDate?: string; toDate?: string }) => void;
  isLoading: boolean;
}

export const DocumentList: React.FC<DocumentListProps> = ({
  documents,
  currentUser,
  onDownload,
  onPreview,
  onOpenUpload,
  onOpenPermissions,
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
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const canUpload = currentUser.role === 'OWNER' || currentUser.role === 'ADMIN';

  return (
    <div>
      {/* Control Toolbar */}
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
            {isLoading ? <RefreshCw size={13} /> : 'Filter'}
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
      {documents.length === 0 ? (
        <div className="zero-trust-empty-card">
          <div className="zero-trust-empty-icon">
            {currentUser.email === 'eve@trustvault.local' ? <ShieldAlert size={22} /> : <Lock size={22} />}
          </div>
          <h4>
            {currentUser.email === 'eve@trustvault.local'
              ? '404 Information Barrier Active (Zero-Trust Enforced)'
              : 'No Documents Match Query'}
          </h4>
          <p>
            {currentUser.email === 'eve@trustvault.local'
              ? 'Principal eve@trustvault.local has zero explicit permissions. The DAL layer returns 404 (Not Found) rather than 403 to prevent metadata or existence leakage.'
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
              {documents.map((doc) => {
                const isOwner = doc.owner?.id === currentUser.id || doc.ownerId === currentUser.id;
                const myGrant = Array.isArray(doc.permissions) && doc.permissions.length > 0 ? doc.permissions[0] : null;
                const hasGrant = !!myGrant;
                const isPreviewOnly = !isOwner && !!myGrant?.previewOnly;
                const isBurnOnDownload = !isOwner && !!myGrant?.burnOnDownload;
                const canDownload = (isOwner || hasGrant) && !isPreviewOnly;
                const canPreview = isOwner || hasGrant;
                const canManage = isOwner; // L-03: Strict owner-only delegation
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
                        <div>
                          <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span>{doc.title}</span>
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
                                  fontSize: '10px'
                                }}
                                title="Single-use transfer: Access grant closes immediately upon successful download"
                              >
                                <Flame size={10} />
                                <span>Burn-on-Download</span>
                              </span>
                            )}
                            {isPreviewOnly && (
                              <span
                                className="category-pill"
                                style={{
                                  display: 'inline-flex',
                                  alignItems: 'center',
                                  gap: '3px',
                                  borderColor: 'var(--color-indigo-border)',
                                  color: '#c7d2fe',
                                  background: 'var(--color-indigo-subtle)',
                                  fontSize: '10px'
                                }}
                                title="Restricted to in-browser viewing only; raw binary download blocked"
                              >
                                <Eye size={10} />
                                <span>Preview Only</span>
                              </span>
                            )}
                          </div>
                          <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
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

                    <td>
                      {isOwner ? (
                        <span className="status-pill status-SUCCESS">OWNER</span>
                      ) : hasGrant ? (
                        <span className="status-pill status-SUCCESS" style={{ background: 'var(--color-primary-subtle)', color: '#93c5fd', borderColor: 'var(--color-primary-border)' }}>
                          AUTHORIZED READ
                        </span>
                      ) : currentUser.role === 'ADMIN' ? (
                        <span className="status-pill status-FAILED" style={{ background: 'rgba(239, 68, 68, 0.1)', color: '#fca5a5', borderColor: 'rgba(239, 68, 68, 0.25)' }}>
                          ZERO-TRUST OVERSIGHT
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

                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                        {canPreview && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onPreview(doc)}
                            title="In-Browser Ephemeral Preview (Streamed and decrypted directly in memory)"
                            style={isPreviewOnly ? { borderColor: 'rgba(168, 85, 247, 0.4)', color: '#c084fc' } : {}}
                          >
                            <Eye size={12} />
                            <span>Preview</span>
                          </button>
                        )}

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
                        ) : isPreviewOnly ? (
                          <button
                            className="btn btn-secondary btn-sm"
                            disabled
                            style={{ opacity: 0.5, cursor: 'not-allowed', borderColor: 'rgba(168, 85, 247, 0.3)' }}
                            title="Binary download disabled by document policy. Use In-Browser Preview."
                          >
                            <Lock size={12} />
                            <span>Download Disabled</span>
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

                        {canManage && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onOpenPermissions(doc)}
                            title="Manage Access Delegation & Policy Recommender"
                          >
                            <Users size={12} />
                            <span>Access Control</span>
                          </button>
                        )}

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
