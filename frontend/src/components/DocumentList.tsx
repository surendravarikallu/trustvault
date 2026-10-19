import React, { useState } from 'react';
import { Search, Download, Trash2, Users, Upload, Filter, X, FileText } from 'lucide-react';
import type { VaultDocument, User } from '../types';

interface DocumentListProps {
  documents: VaultDocument[];
  currentUser: User;
  onDownload: (doc: VaultDocument) => void;
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

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  const canUpload = currentUser.role === 'OWNER' || currentUser.role === 'ADMIN';

  return (
    <div>
      {/* Search & Actions Toolbar */}
      <div className="toolbar">
        <form onSubmit={handleApplyFilter} style={{ display: 'flex', gap: '10px', flex: 1, flexWrap: 'wrap' }}>
          <div className="search-bar">
            <Search size={16} color="var(--text-muted)" />
            <input
              type="text"
              placeholder="Search documents by name, filename, or description..."
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>

          <button type="submit" className="btn btn-secondary btn-sm">
            Search
          </button>

          <button
            type="button"
            className={`btn btn-sm ${showAdvanced ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => setShowAdvanced(!showAdvanced)}
          >
            <Filter size={14} />
            <span>Filters</span>
          </button>

          {(q || owner || category || fromDate || toDate) && (
            <button type="button" className="btn btn-secondary btn-sm" onClick={handleReset}>
              <X size={14} />
              <span>Reset</span>
            </button>
          )}
        </form>

        {canUpload && (
          <button className="btn btn-primary" onClick={onOpenUpload}>
            <Upload size={16} />
            <span>Upload Document</span>
          </button>
        )}
      </div>

      {/* Advanced Filter Panel */}
      {showAdvanced && (
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-subtle)',
            borderRadius: 'var(--radius-sm)',
            padding: '16px',
            marginBottom: '20px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '12px'
          }}
        >
          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
              Owner Name / Email
            </label>
            <input
              type="text"
              placeholder="e.g. Alice or owner@..."
              value={owner}
              onChange={(e) => setOwner(e.target.value)}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
              Category
            </label>
            <select value={category} onChange={(e) => setCategory(e.target.value)}>
              <option value="">All Categories</option>
              <option value="Legal">Legal</option>
              <option value="Finance">Finance</option>
              <option value="HR">HR</option>
              <option value="Engineering">Engineering</option>
              <option value="Executive">Executive</option>
            </select>
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
              Created From
            </label>
            <input type="date" value={fromDate} onChange={(e) => setFromDate(e.target.value)} />
          </div>

          <div>
            <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
              Created To
            </label>
            <input type="date" value={toDate} onChange={(e) => setToDate(e.target.value)} />
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-end' }}>
            <button className="btn btn-primary btn-sm" onClick={() => handleApplyFilter()} style={{ width: '100%' }}>
              Apply Criteria
            </button>
          </div>
        </div>
      )}

      {/* Documents Table */}
      <div className="table-container">
        {isLoading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading secure documents...
          </div>
        ) : documents.length === 0 ? (
          <div style={{ padding: '60px 20px', textAlign: 'center' }}>
            <FileText size={40} color="var(--text-muted)" style={{ marginBottom: '12px', opacity: 0.5 }} />
            <h3 style={{ fontSize: '1.1rem', marginBottom: '6px' }}>No Accessible Documents Found</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', maxWidth: '420px', margin: '0 auto' }}>
              {currentUser.role === 'VIEWER'
                ? 'You currently have no documents granted to your account. Only files explicitly shared with your email are visible.'
                : 'No documents matched your active search query and permissions predicate.'}
            </p>
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Document Name & Details</th>
                <th>Category</th>
                <th>Owner</th>
                <th>Size</th>
                <th>Access Level</th>
                <th>Uploaded</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {documents.map((doc) => {
                const isOwner = doc.owner.id === currentUser.id;
                const canManage = isOwner;
                const canDelete = isOwner || currentUser.role === 'ADMIN';

                return (
                  <tr key={doc.id}>
                    <td>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '2px' }}>
                        {doc.title}
                      </div>
                      <div className="mono" style={{ fontSize: '0.75rem' }}>
                        {doc.originalFilename}
                      </div>
                      {doc.description && (
                        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
                          {doc.description}
                        </div>
                      )}
                    </td>
                    <td>
                      <span className="role-tag" style={{ background: 'rgba(255, 255, 255, 0.05)', color: 'var(--text-secondary)' }}>
                        {doc.category}
                      </span>
                    </td>
                    <td>
                      <div style={{ fontSize: '0.85rem' }}>{doc.owner.name}</div>
                      <div className="mono" style={{ fontSize: '0.72rem' }}>{doc.owner.email}</div>
                    </td>
                    <td className="mono">{formatSize(doc.fileSize)}</td>
                    <td>
                      {isOwner ? (
                        <span className="status-pill status-SUCCESS">Owner</span>
                      ) : currentUser.role === 'ADMIN' ? (
                        <span className="status-pill status-FAILED">Admin (Metadata Only)</span>
                      ) : doc.permissions && doc.permissions.length > 0 ? (
                        <span className="status-pill status-SUCCESS">{doc.permissions[0].permissionLevel} Grant</span>
                      ) : (
                        <span className="status-pill">Unknown</span>
                      )}
                    </td>
                    <td className="mono" style={{ fontSize: '0.78rem' }}>
                      {new Date(doc.createdAt).toLocaleDateString()}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '6px' }}>
                        <button
                          className="btn btn-secondary btn-sm"
                          onClick={() => onDownload(doc)}
                          title="Stream authenticated in-memory blob download"
                        >
                          <Download size={14} />
                          <span>Download</span>
                        </button>

                        {canManage && (
                          <button
                            className="btn btn-secondary btn-sm"
                            onClick={() => onOpenPermissions(doc)}
                            title="Manage access grants and AI suggestions"
                          >
                            <Users size={14} />
                            <span>Share</span>
                          </button>
                        )}

                        {canDelete && (
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => onDeleteDocument(doc.id)}
                            title="Soft-delete document"
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
