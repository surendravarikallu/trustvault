import React, { useState, useEffect } from 'react';
import { X, History, FileText, Check, Copy, RefreshCw, AlertCircle } from 'lucide-react';
import type { VaultDocument } from '../types';
import { fetchDocumentVersions, type DocumentVersionInfo } from '../api';

interface VersionHistoryModalProps {
  isOpen: boolean;
  onClose: () => void;
  document: VaultDocument | null;
}

export const VersionHistoryModal: React.FC<VersionHistoryModalProps> = ({
  isOpen,
  onClose,
  document
}) => {
  const [versions, setVersions] = useState<DocumentVersionInfo[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && document) {
      loadVersions();
    }
  }, [isOpen, document]);

  const loadVersions = async () => {
    if (!document) return;
    setIsLoading(true);
    setError(null);
    try {
      const data = await fetchDocumentVersions(document.id);
      setVersions(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load version history.');
    } finally {
      setIsLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  if (!isOpen || !document) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '680px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <History size={16} color="var(--color-primary)" />
            <span style={{ fontWeight: 600, fontSize: '13px' }}>Cryptographic Version History</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
          >
            <X size={16} />
          </button>
        </div>

        <div className="modal-body">
          {/* Document Context Header */}
          <div
            style={{
              background: 'var(--bg-surface-raised)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-sm)',
              padding: '12px 14px',
              marginBottom: '16px'
            }}
          >
            <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)', marginBottom: '2px' }}>
              {document.title}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
              Current Active: {document.originalFilename} · {formatSize(document.fileSize)}
            </div>
          </div>

          {error && (
            <div
              style={{
                background: 'var(--color-rose-subtle)',
                border: '1px solid var(--color-rose-border)',
                color: '#fca5a5',
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '12px',
                marginBottom: '14px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              <AlertCircle size={14} />
              <span>{error}</span>
            </div>
          )}

          {isLoading ? (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)', fontSize: '12px' }}>
              <RefreshCw size={16} className="spin-icon" style={{ display: 'inline', marginRight: '6px' }} />
              Querying immutable version chain...
            </div>
          ) : versions.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '30px', color: 'var(--text-muted)', fontSize: '12px' }}>
              This document is at version 1 (initial upload). No previous revisions archived.
            </div>
          ) : (
            <div className="data-table-wrapper">
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: '60px' }}>Rev #</th>
                    <th>Filename</th>
                    <th>Size</th>
                    <th>Created At</th>
                    <th>SHA-256 Digest</th>
                  </tr>
                </thead>
                <tbody>
                  {versions.map((v) => (
                    <tr key={v.id}>
                      <td>
                        <span
                          className="mono-cell"
                          style={{
                            fontWeight: 700,
                            color: '#60a5fa',
                            background: 'rgba(59, 130, 246, 0.1)',
                            padding: '2px 6px',
                            borderRadius: 'var(--radius-xs)'
                          }}
                        >
                          v{v.versionNumber}
                        </span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <FileText size={13} color="var(--text-dim)" />
                          <span style={{ fontSize: '12px', color: 'var(--text-primary)' }}>{v.originalFilename}</span>
                        </div>
                      </td>
                      <td className="mono-cell">{formatSize(v.fileSize)}</td>
                      <td style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                        {new Date(v.createdAt).toLocaleString()}
                      </td>
                      <td>
                        <div className="hash-pill" title={v.fileHash}>
                          <span>{v.fileHash.substring(0, 10)}...</span>
                          <button
                            type="button"
                            onClick={() => copyToClipboard(v.fileHash)}
                            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'inherit', padding: '0 2px' }}
                            title="Copy Full SHA-256 Hash"
                          >
                            {copiedHash === v.fileHash ? <Check size={11} color="var(--color-emerald)" /> : <Copy size={11} />}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button type="button" className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
