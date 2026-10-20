import React, { useEffect } from 'react';
import { Eye, Download, ExternalLink, X, Shield, Lock, FileText } from 'lucide-react';
import type { VaultDocument } from '../types';

interface DocumentPreviewModalProps {
  document: VaultDocument;
  blobUrl: string;
  mimeType: string;
  canDownload: boolean;
  onClose: () => void;
  onDownload: () => void;
}

export const DocumentPreviewModal: React.FC<DocumentPreviewModalProps> = ({
  document: doc,
  blobUrl,
  mimeType,
  canDownload,
  onClose,
  onDownload
}) => {
  // Clean up Blob object URL when modal is closed to prevent browser memory leaks
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      if (blobUrl) {
        window.URL.revokeObjectURL(blobUrl);
      }
    };
  }, [blobUrl, onClose]);

  const handleOpenNewTab = () => {
    window.open(blobUrl, '_blank');
  };

  const isPdf = mimeType.includes('pdf') || doc.originalFilename.toLowerCase().endsWith('.pdf');

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        style={{
          maxWidth: '1000px',
          width: '95vw',
          maxHeight: '94vh',
          display: 'flex',
          flexDirection: 'column'
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: 'var(--radius-sm)',
                background: 'var(--color-primary-subtle)',
                border: '1px solid var(--color-primary-border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: 'var(--color-primary)',
                flexShrink: 0
              }}
            >
              <Eye size={16} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  flexWrap: 'wrap'
                }}
              >
                <h3
                  style={{
                    margin: 0,
                    fontSize: '15px',
                    fontWeight: 700,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    maxWidth: '420px'
                  }}
                  title={doc.title}
                >
                  {doc.title}
                </h3>
                <span className="category-pill">{doc.category}</span>
                <span className="brand-badge" style={{ fontSize: '9px' }}>
                  {doc.originalFilename}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px', fontFamily: 'var(--font-mono)' }}>
                SHA-256: {doc.fileHash ? `${doc.fileHash.substring(0, 16)}...` : 'Verified-Blob'}
              </div>
            </div>
          </div>

          {/* Action Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleOpenNewTab}
              title="Open stream in a dedicated browser tab"
              style={{ display: 'flex', alignItems: 'center', gap: '5px' }}
            >
              <ExternalLink size={12} />
              <span>Open Tab</span>
            </button>

            {canDownload ? (
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={onDownload}
                title="Save binary file to disk"
                style={{ display: 'flex', alignItems: 'center', gap: '5px' }}
              >
                <Download size={12} />
                <span>Save</span>
              </button>
            ) : (
              <span
                className="category-pill"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '4px',
                  borderColor: 'rgba(168, 85, 247, 0.4)',
                  color: '#c084fc',
                  background: 'rgba(168, 85, 247, 0.1)',
                  padding: '4px 8px',
                  fontSize: '11px'
                }}
                title="Binary file download is prohibited by owner document security policy"
              >
                <Lock size={11} />
                <span>Preview Only Policy</span>
              </span>
            )}

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={onClose}
              title="Close Preview (Escape)"
              style={{ padding: '4px 8px' }}
            >
              <X size={14} />
            </button>
          </div>
        </div>

        {/* Modal Body / Embedded Preview Viewport */}
        <div
          className="modal-body"
          style={{
            padding: 0,
            flex: 1,
            minHeight: '520px',
            height: '75vh',
            display: 'flex',
            flexDirection: 'column',
            background: '#070a10',
            overflow: 'hidden'
          }}
        >
          {isPdf ? (
            <iframe
              src={`${blobUrl}#toolbar=1&navpanes=0`}
              title={doc.title}
              width="100%"
              height="100%"
              style={{
                border: 'none',
                flex: 1,
                width: '100%',
                height: '100%',
                background: '#ffffff',
                display: 'block'
              }}
            />
          ) : (
            <div
              style={{
                flex: 1,
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                padding: '40px',
                textAlign: 'center'
              }}
            >
              <FileText size={48} color="var(--text-secondary)" style={{ marginBottom: '16px' }} />
              <h4 style={{ fontSize: '16px', color: 'var(--text-primary)', marginBottom: '8px' }}>
                Preview Ready: {doc.originalFilename}
              </h4>
              <p style={{ color: 'var(--text-muted)', fontSize: '12px', maxWidth: '420px', marginBottom: '20px' }}>
                This file format ({mimeType}) can be inspected directly in a new window or saved locally.
              </p>
              <button
                type="button"
                className="btn btn-primary"
                onClick={handleOpenNewTab}
                style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                <ExternalLink size={14} />
                <span>Open Preview in Full Window</span>
              </button>
            </div>
          )}
        </div>

        {/* Modal Footer Security Context */}
        <div
          className="modal-footer"
          style={{
            justifyContent: 'space-between',
            padding: '8px 18px',
            fontSize: '11px',
            color: 'var(--text-dim)',
            background: '#06090e'
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Shield size={12} color="var(--color-emerald)" />
            <span>Encrypted Stream Decrypted In-Memory (Zero Client Disk Footprint)</span>
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-xs"
            onClick={onClose}
          >
            Close Viewer
          </button>
        </div>
      </div>
    </div>
  );
};
