import React, { useEffect, useRef, useState } from 'react';
import { Eye, Download, ExternalLink, X, Shield, Lock, FileText, ChevronLeft, ChevronRight, ZoomIn, ZoomOut } from 'lucide-react';
import * as pdfjsLib from 'pdfjs-dist';
import pdfWorker from 'pdfjs-dist/build/pdf.worker.mjs?url';
import type { VaultDocument } from '../types';

// Set up Mozilla PDF.js web worker
pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorker;

interface DocumentPreviewModalProps {
  document: VaultDocument;
  blobUrl: string;
  mimeType: string;
  arrayBuffer?: ArrayBuffer;
  canDownload: boolean;
  onClose: () => void;
  onDownload: () => void;
}

export const DocumentPreviewModal: React.FC<DocumentPreviewModalProps> = ({
  document: doc,
  blobUrl,
  mimeType,
  arrayBuffer,
  canDownload,
  onClose,
  onDownload
}) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [pdfDoc, setPdfDoc] = useState<any>(null);
  const [currentPage, setCurrentPage] = useState<number>(1);
  const [totalPages, setTotalPages] = useState<number>(1);
  const [scale, setScale] = useState<number>(1.2);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [renderError, setRenderError] = useState<string | null>(null);
  const [textContent, setTextContent] = useState<string | null>(null);

  const isPdf = mimeType.includes('pdf') || doc.originalFilename.toLowerCase().endsWith('.pdf');
  const isText = mimeType.startsWith('text/') || mimeType.includes('json') || mimeType.includes('markdown') || doc.originalFilename.endsWith('.txt') || doc.originalFilename.endsWith('.md');

  // Clean up Blob URL on unmount
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      if (blobUrl) window.URL.revokeObjectURL(blobUrl);
    };
  }, [blobUrl, onClose]);

  // Load PDF document using PDF.js
  useEffect(() => {
    let isCancelled = false;

    async function loadPdf() {
      if (!isPdf) {
        setIsLoading(false);
        // If text, decode text content
        if (arrayBuffer && isText) {
          try {
            const decoded = new TextDecoder('utf-8').decode(arrayBuffer);
            setTextContent(decoded);
          } catch {
            // Ignore decoding error
          }
        }
        return;
      }

      setIsLoading(true);
      setRenderError(null);

      try {
        let docData: any;
        if (arrayBuffer && arrayBuffer.byteLength > 0) {
          docData = { data: new Uint8Array(arrayBuffer) };
        } else {
          docData = { url: blobUrl };
        }

        const loadingTask = pdfjsLib.getDocument(docData);
        const loadedPdf = await loadingTask.promise;

        if (!isCancelled) {
          setPdfDoc(loadedPdf);
          setTotalPages(loadedPdf.numPages);
          setCurrentPage(1);
          setIsLoading(false);
        }
      } catch (err: any) {
        console.error('PDF.js loading failed:', err);
        if (!isCancelled) {
          setRenderError(err.message || 'Unable to parse PDF stream in canvas.');
          setIsLoading(false);
        }
      }
    }

    loadPdf();

    return () => {
      isCancelled = true;
    };
  }, [isPdf, isText, arrayBuffer, blobUrl]);

  // Render active page to canvas
  useEffect(() => {
    let isCancelled = false;

    async function renderPage() {
      if (!pdfDoc || !canvasRef.current) return;

      try {
        const page = await pdfDoc.getPage(currentPage);
        if (isCancelled) return;

        const viewport = page.getViewport({ scale });
        const canvas = canvasRef.current;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        canvas.height = viewport.height;
        canvas.width = viewport.width;

        const renderContext = {
          canvasContext: ctx,
          viewport
        };

        await page.render(renderContext).promise;
      } catch (err) {
        console.error('Failed to render PDF page on canvas:', err);
      }
    }

    renderPage();

    return () => {
      isCancelled = true;
    };
  }, [pdfDoc, currentPage, scale]);

  const handleOpenNewTab = () => {
    window.open(blobUrl, '_blank');
  };

  const handlePrevPage = () => {
    if (currentPage > 1) setCurrentPage((prev) => prev - 1);
  };

  const handleNextPage = () => {
    if (currentPage < totalPages) setCurrentPage((prev) => prev + 1);
  };

  const handleZoomIn = () => {
    setScale((prev) => Math.min(prev + 0.2, 2.5));
  };

  const handleZoomOut = () => {
    setScale((prev) => Math.max(prev - 0.2, 0.6));
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div
        className="modal-content"
        style={{
          maxWidth: '1080px',
          width: '95vw',
          maxHeight: '94vh',
          display: 'flex',
          flexDirection: 'column'
        }}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
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
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <h3
                  style={{
                    margin: 0,
                    fontSize: '15px',
                    fontWeight: 700,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    maxWidth: '400px'
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

          {/* Action buttons */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
            {/* PDF Controls if multiple pages or zoom */}
            {isPdf && !isLoading && !renderError && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '4px',
                  background: 'var(--bg-surface-raised)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '2px 6px'
                }}
              >
                <button
                  type="button"
                  className="btn btn-secondary btn-xs"
                  onClick={handlePrevPage}
                  disabled={currentPage <= 1}
                  style={{ padding: '2px 5px', opacity: currentPage <= 1 ? 0.4 : 1 }}
                  title="Previous Page"
                >
                  <ChevronLeft size={12} />
                </button>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', padding: '0 4px', color: 'var(--text-secondary)' }}>
                  {currentPage} / {totalPages}
                </span>
                <button
                  type="button"
                  className="btn btn-secondary btn-xs"
                  onClick={handleNextPage}
                  disabled={currentPage >= totalPages}
                  style={{ padding: '2px 5px', opacity: currentPage >= totalPages ? 0.4 : 1 }}
                  title="Next Page"
                >
                  <ChevronRight size={12} />
                </button>

                <div style={{ width: '1px', height: '14px', background: 'var(--border-default)', margin: '0 4px' }} />

                <button
                  type="button"
                  className="btn btn-secondary btn-xs"
                  onClick={handleZoomOut}
                  title="Zoom Out"
                  style={{ padding: '2px 5px' }}
                >
                  <ZoomOut size={12} />
                </button>
                <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--text-dim)' }}>
                  {Math.round(scale * 100)}%
                </span>
                <button
                  type="button"
                  className="btn btn-secondary btn-xs"
                  onClick={handleZoomIn}
                  title="Zoom In"
                  style={{ padding: '2px 5px' }}
                >
                  <ZoomIn size={12} />
                </button>
              </div>
            )}

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
                <span>Preview Only</span>
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

        {/* Viewport */}
        <div
          className="modal-body"
          style={{
            padding: 0,
            flex: 1,
            minHeight: '540px',
            height: '75vh',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: isLoading ? 'center' : 'flex-start',
            background: '#04070c',
            overflow: 'auto',
            position: 'relative'
          }}
        >
          {isLoading ? (
            <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-secondary)' }}>
              <div className="status-dot active" style={{ margin: '0 auto 12px auto', width: '10px', height: '10px' }} />
              <div style={{ fontSize: '13px', fontWeight: 600 }}>Streaming & Rendering Document...</div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px' }}>
                Decrypting AES-256-GCM envelope payload in memory
              </div>
            </div>
          ) : isPdf && !renderError ? (
            <div style={{ padding: '24px', display: 'flex', justifyContent: 'center', width: '100%', minHeight: 'min-content' }}>
              <canvas
                ref={canvasRef}
                style={{
                  boxShadow: '0 8px 30px rgba(0, 0, 0, 0.7)',
                  borderRadius: '4px',
                  background: '#ffffff',
                  maxWidth: '100%',
                  height: 'auto'
                }}
              />
            </div>
          ) : isText && textContent !== null ? (
            <div style={{ padding: '24px', width: '100%', height: '100%', overflow: 'auto' }}>
              <pre
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '16px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12px',
                  color: 'var(--text-primary)',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                  margin: 0
                }}
              >
                {textContent}
              </pre>
            </div>
          ) : (
            /* Fallback Card */
            <div
              style={{
                textAlign: 'center',
                padding: '40px 20px',
                maxWidth: '460px'
              }}
            >
              <FileText size={48} color="var(--text-secondary)" style={{ marginBottom: '16px' }} />
              <h4 style={{ fontSize: '16px', color: 'var(--text-primary)', marginBottom: '8px' }}>
                {doc.title}
              </h4>
              <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginBottom: '16px', lineHeight: 1.5 }}>
                {renderError
                  ? 'This document uses a compact or binary structure that can be viewed in your browser tab.'
                  : `Preview stream ready for ${doc.originalFilename} (${mimeType}).`}
              </p>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleOpenNewTab}
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                >
                  <ExternalLink size={14} />
                  <span>Open Full Viewer in New Tab</span>
                </button>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
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
            <span>TrustValt Cryptographic Decryption (Zero Disk Residue) • trustvalt.me</span>
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
