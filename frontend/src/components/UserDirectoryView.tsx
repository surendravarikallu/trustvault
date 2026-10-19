import React, { useState, useEffect } from 'react';
import { Key, UserX } from 'lucide-react';
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
      setMsg(`Updated user role to ${newRole}. Token version incremented; active sessions invalidated instantly.`);
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
      setMsg(`Deactivated user ${name}. All sessions terminated.`);
      await loadUsers();
    } catch (err: any) {
      setError(err.message);
    }
  };

  return (
    <div>
      <div
        style={{
          background: 'rgba(99, 102, 241, 0.05)',
          border: '1px solid rgba(99, 102, 241, 0.2)',
          borderRadius: 'var(--radius-sm)',
          padding: '14px 18px',
          marginBottom: '20px',
          fontSize: '0.85rem',
          color: 'var(--text-secondary)'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-indigo)', fontWeight: 600, marginBottom: '4px' }}>
          <Key size={16} />
          <span>Real-Time Role Management & Instant Session Revocation (L-01)</span>
        </div>
        Promoting or demoting a user or deactivating their account increments the user's <span className="mono">tokenVersion</span> in PostgreSQL. Active JWTs for that account are blocked on their very next HTTP request.
      </div>

      {msg && (
        <div
          style={{
            background: 'var(--accent-emerald-subtle)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: 'var(--accent-emerald)',
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.85rem',
            marginBottom: '16px'
          }}
        >
          {msg}
        </div>
      )}

      {error && (
        <div
          style={{
            background: 'var(--accent-rose-subtle)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            color: 'var(--accent-rose)',
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            fontSize: '0.85rem',
            marginBottom: '16px'
          }}
        >
          {error}
        </div>
      )}

      <div className="table-container">
        {isLoading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading enterprise directory...
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>User Details</th>
                <th>Current Role</th>
                <th>Status</th>
                <th>Token Version</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.id === currentUser.id;

                return (
                  <tr key={u.id}>
                    <td>
                      <div style={{ fontWeight: 600 }}>{u.name}</div>
                      <div className="mono" style={{ fontSize: '0.75rem' }}>{u.email}</div>
                    </td>
                    <td>
                      <span className={`role-tag role-${u.role}`}>{u.role}</span>
                    </td>
                    <td>
                      <span className={`status-pill ${u.isActive !== false ? 'status-SUCCESS' : 'status-DENIED'}`}>
                        {u.isActive !== false ? 'Active' : 'Deactivated'}
                      </span>
                    </td>
                    <td className="mono">v{u.tokenVersion || 1}</td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '8px' }}>
                        <select
                          value={u.role}
                          disabled={isSelf}
                          onChange={(e) => handleRoleChange(u.id, e.target.value as Role)}
                          style={{ padding: '4px 8px', fontSize: '0.775rem' }}
                        >
                          <option value="VIEWER">VIEWER</option>
                          <option value="OWNER">OWNER</option>
                          <option value="ADMIN">ADMIN</option>
                        </select>

                        {!isSelf && u.isActive !== false && (
                          <button
                            className="btn btn-danger btn-sm"
                            onClick={() => handleDeactivate(u.id, u.name)}
                            title="Deactivate account"
                          >
                            <UserX size={12} />
                            <span>Deactivate</span>
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
