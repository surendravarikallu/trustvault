import React, { useState, useEffect } from 'react';
import { KeyRound, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';
import type { User, Role } from '../types';
import { fetchAllUsers, changeUserRole, deactivateUser } from '../api';

interface UserDirectoryViewProps {
  token: string;
  currentUser: User;
}

export const UserDirectoryView: React.FC<UserDirectoryViewProps> = ({ token, currentUser }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    setIsLoading(true);
    try {
      const data = await fetchAllUsers(token);
      setUsers(data.users || []);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  };

  const handleRoleChange = async (userId: string, newRole: Role) => {
    setError(null);
    setMsg(null);
    try {
      await changeUserRole(userId, newRole, token);
      setMsg(`Updated role to ${newRole}. Token version incremented in PostgreSQL; active sessions invalidated instantly.`);
      await loadUsers();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const handleDeactivate = async (userId: string, name: string) => {
    if (!window.confirm(`Deactivate user ${name}? This terminates all active sessions immediately.`)) {
      return;
    }
    setError(null);
    setMsg(null);
    try {
      await deactivateUser(userId, token);
      setMsg(`Deactivated user ${name}. All active JWTs blocked.`);
      await loadUsers();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div>
      {/* Enterprise Security Architecture Banner */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-sm)',
          padding: '12px 16px',
          marginBottom: '16px',
          fontSize: '12px',
          color: 'var(--text-secondary)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: '#93c5fd', fontWeight: 600, marginBottom: '4px' }}>
          <KeyRound size={14} />
          <span>Real-Time Role Governance & Monotonic Session Revocation (L-01)</span>
          {isLoading && <RefreshCw size={12} className="spin-icon" style={{ marginLeft: 'auto' }} />}
        </div>
        Changing a user's role or deactivating an identity atomically increments <span className="mono-cell">tokenVersion</span> in PostgreSQL. The authentication middleware verifies the database tokenVersion on every request, neutralizing stolen or stale JWT tokens without requiring distributed Redis blacklists.
      </div>

      {msg && (
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
          <span>{msg}</span>
        </div>
      )}

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

      {/* User Directory Table */}
      <div className="data-table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Identity</th>
              <th>Corporate Email</th>
              <th>Role Assignment</th>
              <th>Token Version</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => {
              const isSelf = u.id === currentUser.id;

              return (
                <tr key={u.id}>
                  <td>
                    <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)' }}>
                      {u.name} {isSelf && <span style={{ fontSize: '10px', color: 'var(--text-dim)' }}>(Current)</span>}
                    </div>
                  </td>

                  <td className="mono-cell" style={{ fontSize: '11px' }}>
                    {u.email}
                  </td>

                  <td>
                    {isSelf ? (
                      <span className={`role-pill role-${u.role}`}>{u.role}</span>
                    ) : (
                      <select
                        value={u.role}
                        onChange={(e) => handleRoleChange(u.id, e.target.value as Role)}
                        style={{ padding: '3px 8px', fontSize: '11px', width: 'auto' }}
                      >
                        <option value="ADMIN">ADMIN</option>
                        <option value="OWNER">OWNER</option>
                        <option value="VIEWER">VIEWER</option>
                      </select>
                    )}
                  </td>

                  <td className="mono-cell" style={{ fontSize: '11px' }}>
                    v{u.tokenVersion}
                  </td>

                  <td>
                    {u.isActive ? (
                      <span className="status-pill status-SUCCESS">ACTIVE</span>
                    ) : (
                      <span className="status-pill status-DENIED">DEACTIVATED</span>
                    )}
                  </td>

                  <td style={{ textAlign: 'right' }}>
                    {!isSelf && u.isActive && (
                      <button
                        type="button"
                        className="btn btn-danger btn-xs"
                        onClick={() => handleDeactivate(u.id, u.name)}
                      >
                        Deactivate
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
