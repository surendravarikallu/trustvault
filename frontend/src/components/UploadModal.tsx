import React, { useState } from 'react';
import { X, Upload, AlertCircle } from 'lucide-react';

interface UploadModalProps {
  isOpen: boolean;
  onClose: () => void;
  onUploadSuccess: () => void;
  token: string;
}

export const UploadModal: React.FC<UploadModalProps> = ({ isOpen, onClose, onUploadSuccess, token }) => {
  const [title, setTitle] = useState('');
  const [category, setCategory] = useState('Legal');
  const [description, setDescription] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file to upload.');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    const formData = new FormData();
    formData.append('title', title);
    formData.append('category', category);
    formData.append('description', description);
    formData.append('file', file);

    try {
      const res = await fetch('/api/documents', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      });

      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.error || 'Upload failed.');
      }

      onUploadSuccess();
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Upload size={18} color="var(--accent-emerald)" />
            <h3 style={{ fontSize: '1rem' }}>Upload Document to Vault</h3>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={onClose} style={{ padding: '4px' }}>
            <X size={16} />
          </button>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="modal-body">
            {error && (
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  background: 'var(--accent-rose-subtle)',
                  border: '1px solid rgba(244, 63, 94, 0.3)',
                  color: 'var(--accent-rose)',
                  padding: '10px 14px',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '0.85rem',
                  marginBottom: '16px'
                }}
              >
                <AlertCircle size={16} />
                <span>{error}</span>
              </div>
            )}

            <div className="form-group">
              <label>Document Title *</label>
              <input
                type="text"
                required
                placeholder="e.g. Master Services Agreement 2026"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label>Category *</label>
              <select value={category} onChange={(e) => setCategory(e.target.value)}>
                <option value="Legal">Legal</option>
                <option value="Finance">Finance</option>
                <option value="HR">HR</option>
                <option value="Engineering">Engineering</option>
                <option value="Executive">Executive</option>
                <option value="Operations">Operations</option>
              </select>
            </div>

            <div className="form-group">
              <label>Description (Optional)</label>
              <textarea
                rows={2}
                placeholder="Brief summary of document sensitivity and context..."
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>

            <div className="form-group">
              <label>Select File (Max 15MB) *</label>
              <input
                type="file"
                required
                onChange={(e) => setFile(e.target.files ? e.target.files[0] : null)}
                style={{ padding: '8px' }}
              />
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '6px' }}>
                Permitted extensions: <span className="mono">.pdf, .docx, .xlsx, .txt, .png, .jpg</span> (Magic bytes validated on upload)
              </div>
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
              {isSubmitting ? 'Validating & Uploading...' : 'Upload & Hash'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
