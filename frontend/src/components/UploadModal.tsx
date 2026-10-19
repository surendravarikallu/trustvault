import React, { useState } from 'react';
import { X, Upload, AlertCircle } from 'lucide-react';
import { uploadDocument } from '../api';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  token: string;
  onUploadSuccess: () => void;
}

export const UploadModal: React.FC<UploadModalProps> = ({
  isOpen,
  onClose,
  token,
  onUploadSuccess
}) => {
  const [file, setFile] = useState<File | null>(null);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [category, setCategory] = useState('Legal');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file to upload.');
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('title', title.trim() || file.name);
      formData.append('description', description.trim());
      formData.append('category', category);

      await uploadDocument(formData, token);
      onUploadSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Upload failed.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '520px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Upload size={16} color="var(--color-primary)" />
            <span style={{ fontWeight: 600, fontSize: '13px' }}>Upload Secure Document</span>
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

            <div className="form-group">
              <label>Document Title</label>
              <input
                type="text"
                placeholder="e.g. Master Services Agreement 2026"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label>Classification Category</label>
              <select value={category} onChange={(e) => setCategory(e.target.value)}>
                <option value="Legal">Legal</option>
                <option value="Finance">Finance</option>
                <option value="HR">HR</option>
                <option value="Engineering">Engineering</option>
                <option value="Operations">Operations</option>
              </select>
            </div>

            <div className="form-group">
              <label>Description / Purpose</label>
              <textarea
                rows={3}
                placeholder="Enterprise purpose, security classification, or retention instructions..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label>Select File (Max 25MB)</label>
              <input
                type="file"
                required
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    setFile(e.target.files[0]);
                    if (!title) setTitle(e.target.files[0].name.replace(/\.[^/.]+$/, ''));
                  }
                }}
                style={{ padding: '8px' }}
              />
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px' }}>
                Zero-Trust Signature Inspection: Permitted formats (.pdf, .png, .jpg, .docx, .xlsx, .txt). Windows PE (.exe/.dll) and Linux ELF binaries are rejected via magic-byte buffer analysis.
              </div>
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={isLoading}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={isLoading}>
              {isLoading ? 'Inspecting & Encrypting...' : 'Upload & Encrypt'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
