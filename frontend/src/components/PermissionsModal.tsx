import React, { useState, useEffect } from 'react';
import { X, UserPlus, Trash2, Sparkles, Clock, ShieldCheck, AlertCircle } from 'lucide-react';
import type { VaultDocument, DocumentPermission, ReviewerSuggestion, PermissionLevel } from '../types';
import {
  fetchDocumentPermissions,
  grantPermission,
  revokePermission,
  suggestReviewersWithAI
} from '../api';

interface PermissionsModalProps {
  document: VaultDocument | null;
  isOpen: boolean;
  onClose: () => void;
  token: string;
}

export const PermissionsModal: React.FC<PermissionsModalProps> = ({
  document,
  isOpen,
  onClose,
  token
}) => {
  const [grantees, setGrantees] = useState<DocumentPermission[]>([]);
  const [targetEmail, setTargetEmail] = useState('');
  const [permissionLevel, setPermissionLevel] = useState<PermissionLevel>('READ');
  const [expiresAt, setExpiresAt] = useState('');
  const [suggestions, setSuggestions] = useState<ReviewerSuggestion[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isSuggesting, setIsSuggesting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && document) {
      loadGrantees();
      setSuggestions([]);
      setError(null);
      setSuccessMsg(null);
    }
  }, [isOpen, document]);

  if (!isOpen || !document) return null;

  const loadGrantees = async () => {
    setIsLoading(true);
    try {
      const data = await fetchDocumentPermissions(document.id, token);
      setGrantees(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGrant = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    try {
      await grantPermission(
        document.id,
        targetEmail.trim(),
        permissionLevel,
        expiresAt ? new Date(expiresAt).toISOString() : null,
        token
      );
      setSuccessMsg(`Granted ${permissionLevel} access to ${targetEmail}.`);
      setTargetEmail('');
      setExpiresAt('');
      await loadGrantees();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleRevoke = async (userId: string, email: string) => {
    setError(null);
    setSuccessMsg(null);

    try {
      await revokePermission(document.id, userId, token);
      setSuccessMsg(`Revoked access for ${email} immediately.`);
      await loadGrantees();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleGetAISuggestions = async () => {
    setIsSuggesting(true);
    setError(null);
    try {
      const data = await suggestReviewersWithAI(document.id, token);
      setSuggestions(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsSuggesting(false);
    }
  };

  const applySuggestion = (s: ReviewerSuggestion) => {
    setTargetEmail(s.email);
    setPermissionLevel(s.suggestedPermissionLevel);
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content" style={{ maxWidth: '680px' }}>
        <div className="modal-header">
          <div>
            <h3 style={{ fontSize: '1rem', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldCheck size={18} color="var(--accent-emerald)" />
              <span>Manage Permissions: {document.title}</span>
            </h3>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
              Document Owner: <span style={{ color: 'var(--text-primary)' }}>{document.owner.name}</span> ({document.owner.email})
            </div>
          </div>
          <button className="btn btn-secondary btn-sm" onClick={onClose} style={{ padding: '4px' }}>
            <X size={16} />
          </button>
        </div>

        <div className="modal-body" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
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

          {successMsg && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                background: 'var(--accent-emerald-subtle)',
                border: '1px solid rgba(16, 185, 129, 0.3)',
                color: 'var(--accent-emerald)',
                padding: '10px 14px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '0.85rem',
                marginBottom: '16px'
              }}
            >
              <ShieldCheck size={16} />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Current Grantees List */}
          <div style={{ marginBottom: '24px' }}>
            <h4 style={{ fontSize: '0.875rem', marginBottom: '8px', color: 'var(--text-secondary)' }}>
              Active Authorized Grantees ({grantees.length})
            </h4>

            {isLoading ? (
              <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Loading access list...</div>
            ) : grantees.length === 0 ? (
              <div style={{ padding: '16px', background: 'var(--bg-void)', borderRadius: 'var(--radius-sm)', fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                No active grants. Only the document owner can access this file.
              </div>
            ) : (
              <div style={{ border: '1px solid var(--border-subtle)', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
                <table style={{ fontSize: '0.825rem' }}>
                  <thead>
                    <tr>
                      <th>Collaborator</th>
                      <th>Grant Level</th>
                      <th>Expires</th>
                      <th style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {grantees.map((g) => (
                      <tr key={g.id}>
                        <td>
                          <div style={{ fontWeight: 500 }}>{g.user.name}</div>
                          <div className="mono" style={{ fontSize: '0.725rem' }}>{g.user.email}</div>
                        </td>
                        <td>
                          <span className={`status-pill ${g.permissionLevel === 'EDIT' ? 'status-SUCCESS' : ''}`}>
                            {g.permissionLevel}
                          </span>
                        </td>
                        <td className="mono" style={{ fontSize: '0.75rem' }}>
                          {g.expiresAt ? (
                            <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                              <Clock size={12} />
                              {new Date(g.expiresAt).toLocaleDateString()}
                            </span>
                          ) : (
                            'Permanent'
                          )}
                        </td>
                        <td style={{ textAlign: 'right' }}>
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => handleRevoke(g.user.id, g.user.email)}
                            title="Instant Revocation"
                          >
                            <Trash2 size={12} />
                            <span>Revoke</span>
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Grant New Permission Form */}
          <div
            style={{
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid var(--border-subtle)',
              borderRadius: 'var(--radius-sm)',
              padding: '16px',
              marginBottom: '20px'
            }}
          >
            <h4 style={{ fontSize: '0.875rem', marginBottom: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <UserPlus size={16} color="var(--accent-emerald)" />
              <span>Grant New Access</span>
            </h4>

            <form onSubmit={handleGrant}>
              <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: '10px', marginBottom: '10px' }}>
                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                    User Email *
                  </label>
                  <input
                    type="email"
                    required
                    placeholder="colleague@trustvault.local"
                    value={targetEmail}
                    onChange={(e) => setTargetEmail(e.target.value)}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                    Permission Level *
                  </label>
                  <select
                    value={permissionLevel}
                    onChange={(e) => setPermissionLevel(e.target.value as PermissionLevel)}
                  >
                    <option value="READ">READ (View/Download)</option>
                    <option value="EDIT">EDIT (Replace Versions)</option>
                  </select>
                </div>

                <div>
                  <label style={{ fontSize: '0.75rem', color: 'var(--text-muted)', display: 'block', marginBottom: '4px' }}>
                    Expiration (Optional)
                  </label>
                  <input
                    type="date"
                    value={expiresAt}
                    onChange={(e) => setExpiresAt(e.target.value)}
                  />
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button type="submit" className="btn btn-primary btn-sm">
                  Confirm & Grant Permission
                </button>
              </div>
            </form>
          </div>

          {/* AI-Assisted Reviewer Suggestion Section */}
          <div
            style={{
              background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.06), rgba(16, 185, 129, 0.03))',
              border: '1px solid rgba(99, 102, 241, 0.25)',
              borderRadius: 'var(--radius-sm)',
              padding: '16px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Sparkles size={16} color="var(--accent-indigo)" />
                <h4 style={{ fontSize: '0.875rem' }}>AI Reviewer Assistant</h4>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleGetAISuggestions}
                disabled={isSuggesting}
              >
                {isSuggesting ? 'Analyzing...' : 'Suggest Reviewers'}
              </button>
            </div>

            <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', marginBottom: '12px' }}>
              The AI analyzes document metadata and suggests candidate reviewers. <strong>The machine never widens access automatically</strong>; you must explicitly confirm any grant. Both suggestions and decisions are audited.
            </p>

            {suggestions.length > 0 && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {suggestions.map((s) => (
                  <div
                    key={s.userId}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      background: 'rgba(0, 0, 0, 0.3)',
                      padding: '8px 12px',
                      borderRadius: 'var(--radius-sm)',
                      fontSize: '0.8rem'
                    }}
                  >
                    <div>
                      <div style={{ fontWeight: 500 }}>{s.name} <span className="mono" style={{ color: 'var(--text-muted)' }}>({s.email})</span></div>
                      <div style={{ fontSize: '0.725rem', color: 'var(--accent-indigo)' }}>{s.rationale}</div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={() => applySuggestion(s)}
                    >
                      Pre-fill ({s.suggestedPermissionLevel})
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="modal-footer">
          <button className="btn btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
