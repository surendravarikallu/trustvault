import React, { useState, useEffect } from 'react';
import { X, UserPlus, Trash2, ShieldCheck, AlertCircle, CheckCircle2 } from 'lucide-react';
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
    try {
      const data = await fetchDocumentPermissions(document.id, token);
      setGrantees(data);
    } catch (err: any) {
      setError(err.message);
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
      <div className="modal-content" style={{ maxWidth: '640px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldCheck size={16} color="var(--color-emerald)" />
            <span style={{ fontWeight: 600, fontSize: '13px' }}>
              Access Control List: {document.title}
            </span>
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
          {/* Owner non-transferability badge (L-03) */}
          <div
            style={{
              background: 'var(--bg-surface-raised)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-sm)',
              padding: '10px 14px',
              fontSize: '11px',
              color: 'var(--text-secondary)',
              marginBottom: '16px'
            }}
          >
            <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '2px' }}>
              Document Owner: {document.owner.name} ({document.owner.email})
            </div>
            <span>Enforced Rule (L-03): Only the document owner can grant or revoke permissions. Editors cannot elevate other users.</span>
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

          {successMsg && (
            <div
              style={{
                background: 'var(--color-emerald-subtle)',
                border: '1px solid var(--color-emerald-border)',
                color: '#6ee7b7',
                padding: '8px 12px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '12px',
                marginBottom: '14px',
                display: 'flex',
                alignItems: 'center',
                gap: '8px'
              }}
            >
              <CheckCircle2 size={14} />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Least-Privilege Policy Recommender */}
          <div
            style={{
              background: 'var(--bg-surface-raised)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-sm)',
              padding: '12px',
              marginBottom: '16px'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
              <div>
                <span style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: '#93c5fd' }}>
                  Least-Privilege Policy Recommender
                </span>
                <div style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                  Evaluates document classification and recommends least-privilege candidate reviewers.
                </div>
              </div>
              <button
                type="button"
                className="btn btn-secondary btn-xs"
                onClick={handleGetAISuggestions}
                disabled={isSuggesting}
              >
                {isSuggesting ? 'Analyzing Metadata...' : 'Run Policy Analysis'}
              </button>
            </div>

            {suggestions.length > 0 && (
              <div style={{ marginTop: '10px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                {suggestions.map((s) => (
                  <div
                    key={s.userId}
                    style={{
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: 'var(--radius-xs)',
                      padding: '8px 10px',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between'
                    }}
                  >
                    <div>
                      <div style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-primary)' }}>
                        {s.name} <span className="mono-cell" style={{ fontSize: '10px' }}>({s.email})</span>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '2px' }}>
                        Rationale: {s.rationale} · Suggested Level: <span className="mono-cell" style={{ color: '#93c5fd' }}>{s.suggestedPermissionLevel}</span>
                      </div>
                    </div>
                    <button
                      type="button"
                      className="btn btn-secondary btn-xs"
                      onClick={() => applySuggestion(s)}
                    >
                      Apply To Form
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Grant Permission Form */}
          <form onSubmit={handleGrant} style={{ marginBottom: '20px' }}>
            <div style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Delegate Access Grant
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.2fr 1.5fr auto', gap: '8px', alignItems: 'end' }}>
              <div>
                <label style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-dim)', display: 'block', marginBottom: '3px' }}>
                  User Email
                </label>
                <input
                  type="email"
                  required
                  placeholder="name@trustvault.local"
                  value={targetEmail}
                  onChange={(e) => setTargetEmail(e.target.value)}
                />
              </div>

              <div>
                <label style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-dim)', display: 'block', marginBottom: '3px' }}>
                  Permission
                </label>
                <select value={permissionLevel} onChange={(e) => setPermissionLevel(e.target.value as PermissionLevel)}>
                  <option value="READ">READ (View / Stream)</option>
                  <option value="EDIT">EDIT (Update Metadata)</option>
                </select>
              </div>

              <div>
                <label style={{ fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-dim)', display: 'block', marginBottom: '3px' }}>
                  Expiration (Optional)
                </label>
                <input
                  type="date"
                  value={expiresAt}
                  onChange={(e) => setExpiresAt(e.target.value)}
                />
              </div>

              <button type="submit" className="btn btn-primary" style={{ padding: '7px 12px' }}>
                <UserPlus size={13} />
                <span>Grant</span>
              </button>
            </div>
          </form>

          {/* Active Grantees List */}
          <div>
            <div style={{ fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Active Authorized Grantees ({grantees.length})
            </div>

            {grantees.length === 0 ? (
              <div style={{ textAlign: 'center', padding: '16px', background: 'var(--bg-surface-raised)', borderRadius: 'var(--radius-sm)', color: 'var(--text-muted)', fontSize: '12px' }}>
                No explicit grants active. Only owner has access.
              </div>
            ) : (
              <div className="data-table-wrapper">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Grantee</th>
                      <th>Permission</th>
                      <th>Expiration</th>
                      <th style={{ textAlign: 'right' }}>Revoke</th>
                    </tr>
                  </thead>
                  <tbody>
                    {grantees.map((g) => {
                      const targetUserId = g.user?.id || g.userId || '';
                      return (
                        <tr key={g.id}>
                          <td>
                            <div style={{ fontWeight: 500, fontSize: '12px' }}>{g.user?.name}</div>
                            <div className="mono-cell" style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
                              {g.user?.email}
                            </div>
                          </td>

                          <td>
                            <span className="category-pill" style={{ borderColor: 'var(--color-primary-border)', color: '#93c5fd' }}>
                              {g.permissionLevel}
                            </span>
                          </td>

                          <td className="mono-cell" style={{ fontSize: '11px' }}>
                            {g.expiresAt ? (
                              <span style={{ color: 'var(--color-amber)' }}>
                                Expires {new Date(g.expiresAt).toLocaleDateString()}
                              </span>
                            ) : (
                              <span style={{ color: 'var(--text-dim)' }}>Permanent</span>
                            )}
                          </td>

                          <td style={{ textAlign: 'right' }}>
                            <button
                              type="button"
                              className="btn btn-danger btn-xs"
                              onClick={() => handleRevoke(targetUserId, g.user?.email || 'user')}
                              title="Instant Revocation (Enforces L-02: immediate 404)"
                            >
                              <Trash2 size={11} />
                              <span>Revoke</span>
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
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
