import React, { useState, useEffect } from 'react';
import {
  KeyRound,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  UserPlus,
  Key,
  ShieldAlert,
  X,
  Wand2,
  Search
} from 'lucide-react';
import type { User, Role } from '../types';
import {
  fetchAllUsers,
  changeUserRole,
  deactivateUser,
  apiAdminCreateUser,
  apiAdminResetPassword,
  apiAdminResetMfa
} from '../api';

interface UserDirectoryViewProps {
  token: string;
  currentUser: User;
}

export const UserDirectoryView: React.FC<UserDirectoryViewProps> = ({ token, currentUser }) => {
  const [users, setUsers] = useState<User[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [roleFilter, setRoleFilter] = useState<string>('ALL');

  // Create User Modal State
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createEmail, setCreateEmail] = useState('');
  const [createPassword, setCreatePassword] = useState('');
  const [createRole, setCreateRole] = useState<Role>('VIEWER');
  const [isCreating, setIsCreating] = useState(false);

  // Reset Password Modal State
  const [isResetOpen, setIsResetOpen] = useState(false);
  const [resetTargetUser, setResetTargetUser] = useState<User | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [isResetting, setIsResetting] = useState(false);

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

  const generateStrongPassword = () => {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*';
    let pwd = '';
    for (let i = 0; i < 16; i++) {
      pwd += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return pwd;
  };

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setMsg(null);
    setIsCreating(true);

    try {
      await apiAdminCreateUser(token, {
        name: createName.trim(),
        email: createEmail.trim(),
        password: createPassword,
        role: createRole
      });
      setMsg(`Successfully provisioned account for ${createEmail} with role ${createRole}.`);
      setIsCreateOpen(false);
      setCreateName('');
      setCreateEmail('');
      setCreatePassword('');
      setCreateRole('VIEWER');
      await loadUsers();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsCreating(false);
    }
  };

  const openResetPasswordModal = (user: User) => {
    setResetTargetUser(user);
    setNewPassword(generateStrongPassword());
    setIsResetOpen(true);
    setError(null);
  };

  const handleResetPasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resetTargetUser) return;
    setError(null);
    setMsg(null);
    setIsResetting(true);

    try {
      await apiAdminResetPassword(token, resetTargetUser.id, newPassword);
      setMsg(`Password reset for ${resetTargetUser.email}. Token version incremented and all active sessions revoked.`);
      setIsResetOpen(false);
      setResetTargetUser(null);
      setNewPassword('');
      await loadUsers();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setIsResetting(false);
    }
  };

  const handleResetMfa = async (user: User) => {
    if (!window.confirm(`Emergency Reset 2FA for ${user.name} (${user.email})?\n\nThis will remove their TOTP secret, revoke active sessions, and allow them to log in with password only until 2FA is re-enrolled.`)) {
      return;
    }

    setError(null);
    setMsg(null);
    try {
      await apiAdminResetMfa(token, user.id);
      setMsg(`Emergency 2FA reset completed for ${user.email}. Active sessions revoked.`);
      await loadUsers();
    } catch (err: any) {
      setError(err.message);
    }
  };

  const filteredUsers = users.filter((u) => {
    const matchesSearch =
      u.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      u.email.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesRole = roleFilter === 'ALL' || u.role === roleFilter;
    return matchesSearch && matchesRole;
  });

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
        Admin governance allows provisioning identities, reassigning least-privilege roles, issuing cryptographic password resets, and executing emergency 2FA resets. Every administrative update atomically increments <span className="mono-cell">tokenVersion</span> in PostgreSQL, instantly severing compromised active sessions.
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

      {/* Directory Controls Bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '12px',
          marginBottom: '14px',
          flexWrap: 'wrap'
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '280px' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-dim)' }} />
            <input
              type="text"
              className="form-input"
              placeholder="Search user by name or corporate email..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{ paddingLeft: '32px', height: '32px', fontSize: '12px', width: '100%' }}
            />
          </div>

          <select
            value={roleFilter}
            onChange={(e) => setRoleFilter(e.target.value)}
            className="form-input"
            style={{ width: '130px', height: '32px', fontSize: '12px', padding: '0 8px' }}
          >
            <option value="ALL">All Roles</option>
            <option value="ADMIN">ADMIN</option>
            <option value="OWNER">OWNER</option>
            <option value="VIEWER">VIEWER</option>
          </select>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
            Showing <strong style={{ color: 'var(--text-primary)' }}>{filteredUsers.length}</strong> of {users.length} users
          </div>
          <button
            type="button"
            className="btn btn-primary btn-sm"
            onClick={() => {
              setCreatePassword(generateStrongPassword());
              setIsCreateOpen(true);
            }}
          >
            <UserPlus size={13} />
            <span>Provision New User</span>
          </button>
        </div>
      </div>

      {/* User Directory Table */}
      <div className="data-table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th>Identity</th>
              <th>Corporate Email</th>
              <th>Role Assignment</th>
              <th>2FA Status</th>
              <th>Token Version</th>
              <th>Status</th>
              <th style={{ textAlign: 'right' }}>Administrative Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredUsers.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '32px', color: 'var(--text-dim)' }}>
                  No users found matching "{searchQuery}"
                </td>
              </tr>
            ) : (
              filteredUsers.map((u) => {
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

                  <td>
                    {u.mfaEnabled ? (
                      <span className="status-pill status-SUCCESS" style={{ fontSize: '10px' }}>
                        2FA ACTIVE
                      </span>
                    ) : (
                      <span
                        className="status-pill"
                        style={{
                          fontSize: '10px',
                          background: 'rgba(255,255,255,0.04)',
                          color: 'var(--text-dim)',
                          borderColor: 'var(--border-subtle)'
                        }}
                      >
                        NOT CONFIGURED
                      </span>
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
                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                      <button
                        type="button"
                        className="btn btn-secondary btn-xs"
                        onClick={() => openResetPasswordModal(u)}
                        title="Admin Reset Password (Invalidates sessions)"
                      >
                        <Key size={11} />
                        <span>Reset Pwd</span>
                      </button>

                      <button
                        type="button"
                        className="btn btn-secondary btn-xs"
                        onClick={() => handleResetMfa(u)}
                        disabled={!u.mfaEnabled}
                        title={
                          u.mfaEnabled
                            ? 'Emergency Reset 2FA (Clears TOTP secret and revokes sessions)'
                            : '2FA not enabled for this user'
                        }
                        style={{
                          opacity: u.mfaEnabled ? 1 : 0.4,
                          cursor: u.mfaEnabled ? 'pointer' : 'not-allowed'
                        }}
                      >
                        <ShieldAlert size={11} color={u.mfaEnabled ? 'var(--color-amber)' : 'inherit'} />
                        <span>Reset 2FA</span>
                      </button>

                      {!isSelf && u.isActive && (
                        <button
                          type="button"
                          className="btn btn-danger btn-xs"
                          onClick={() => handleDeactivate(u.id, u.name)}
                          title="Immediately terminate account and active tokens"
                        >
                          Deactivate
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            }))}
          </tbody>
        </table>
      </div>

      {/* Provision User Modal */}
      {isCreateOpen && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '480px' }}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <UserPlus size={16} color="#93c5fd" />
                <span style={{ fontWeight: 600, fontSize: '13px' }}>Provision New Identity</span>
              </div>
              <button
                type="button"
                onClick={() => setIsCreateOpen(false)}
                style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleCreateSubmit}>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                    Full Name
                  </label>
                  <input
                    type="text"
                    required
                    placeholder="e.g. Carol Danvers"
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                    Corporate Email
                  </label>
                  <input
                    type="email"
                    required
                    placeholder="carol@trustvault.local"
                    value={createEmail}
                    onChange={(e) => setCreateEmail(e.target.value)}
                  />
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                      Initial Password
                    </label>
                    <button
                      type="button"
                      className="btn btn-secondary btn-xs"
                      onClick={() => setCreatePassword(generateStrongPassword())}
                      style={{ padding: '2px 6px', fontSize: '10px' }}
                    >
                      <Wand2 size={10} />
                      <span>Generate</span>
                    </button>
                  </div>
                  <input
                    type="text"
                    required
                    minLength={8}
                    value={createPassword}
                    onChange={(e) => setCreatePassword(e.target.value)}
                    style={{ fontFamily: 'var(--font-mono)' }}
                  />
                </div>

                <div>
                  <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>
                    Assigned Role
                  </label>
                  <select
                    value={createRole}
                    onChange={(e) => setCreateRole(e.target.value as Role)}
                  >
                    <option value="VIEWER">VIEWER (Read & Ephemeral View Grants)</option>
                    <option value="OWNER">OWNER (Upload, Authorize, Delegate)</option>
                    <option value="ADMIN">ADMIN (System Governance & Audit Oversight)</option>
                  </select>
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setIsCreateOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isCreating}
                >
                  {isCreating ? 'Provisioning...' : 'Provision User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Admin Password Reset Modal */}
      {isResetOpen && resetTargetUser && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '480px' }}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Key size={16} color="var(--color-amber)" />
                <span style={{ fontWeight: 600, fontSize: '13px' }}>
                  Admin Password Reset: {resetTargetUser.name}
                </span>
              </div>
              <button
                type="button"
                onClick={() => setIsResetOpen(false)}
                style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                <X size={16} />
              </button>
            </div>

            <form onSubmit={handleResetPasswordSubmit}>
              <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div
                  style={{
                    background: 'var(--bg-surface-raised)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px 14px',
                    fontSize: '11px',
                    color: 'var(--text-secondary)'
                  }}
                >
                  <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '2px' }}>
                    Target Account: {resetTargetUser.email}
                  </div>
                  <span>
                    Enforced Security Rule (L-01): Setting a new password increments the user's <span className="mono-cell">tokenVersion</span>, immediately revoking all active JWT sessions on all devices.
                  </span>
                </div>

                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                    <label style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                      New Password
                    </label>
                    <button
                      type="button"
                      className="btn btn-secondary btn-xs"
                      onClick={() => setNewPassword(generateStrongPassword())}
                      style={{ padding: '2px 6px', fontSize: '10px' }}
                    >
                      <Wand2 size={10} />
                      <span>Generate</span>
                    </button>
                  </div>
                  <input
                    type="text"
                    required
                    minLength={8}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    style={{ fontFamily: 'var(--font-mono)' }}
                  />
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setIsResetOpen(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isResetting}
                >
                  {isResetting ? 'Updating...' : 'Confirm Reset Password'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
