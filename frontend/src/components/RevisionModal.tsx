import React, { useState } from 'react';
import { X, RefreshCw, AlertCircle, UploadCloud } from 'lucide-react';
import type { VaultDocument } from '../types';
import { replaceDocument } from '../api';

interface RevisionModalProps {
  isOpen: boolean;
  onClose: () => void;
  document: VaultDocument | null;
  onSuccess: () => void;
}

export const RevisionModal: React.FC<RevisionModalProps> = ({
  isOpen,
  onClose,
  document,
  onSuccess
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen || !document) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a replacement file to upload.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      await replaceDocument(document.id, file);
      onSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to upload replacement version.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '520px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <RefreshCw size={16} color="var(--color-amber)" />
            <span style={{ fontWeight: 600, fontSize: '13px' }}>Upload New Version Revision</span>
          </div>
          <button
            type="button"
            onClick={onClose}
            style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
          >
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
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

            {/* Current Version Summary Card */}
            <div
              style={{
                background: 'var(--bg-surface-raised)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px 14px',
                marginBottom: '16px'
              }}
            >
              <div style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '6px' }}>
                Target Document
              </div>
              <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)', marginBottom: '2px' }}>
                {document.title}
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                <span>Active: {document.originalFilename}</span>
                <span>SHA-256: {document.fileHash ? `${document.fileHash.substring(0, 12)}...` : 'Verified'}</span>
              </div>
            </div>

            <div className="form-group">
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <UploadCloud size={14} color="var(--color-primary)" />
                <span>Replacement File Payload</span>
              </label>
              <input
                type="file"
                required
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    setFile(e.target.files[0]);
                  }
                }}
                style={{ padding: '8px' }}
              />
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px', lineHeight: 1.4 }}>
                <strong>Cryptographic Versioning:</strong> Uploading a new file preserves the existing version immutably in the version ledger. All active access permissions are automatically retained for the new version.
              </div>
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={isLoading}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={isLoading} style={{ background: '#d97706', borderColor: '#b45309' }}>
              <RefreshCw size={13} className={isLoading ? 'spin-icon' : ''} />
              <span>{isLoading ? 'Encrypting & Committing Revision...' : 'Commit New Version'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
