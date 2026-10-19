import React, { useState } from 'react';
import { Shield, ArrowRight, Lock, AlertCircle } from 'lucide-react';
import { apiLogin } from '../api';
import type { User } from '../types';

interface LoginViewProps {
  onLoginSuccess: (token: string, user: User) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const data = await apiLogin(email, password);
      onLoginSuccess(data.token, data.user);
    } catch (err: any) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickPersona = async (pEmail: string, pPass: string) => {
    setEmail(pEmail);
    setPassword(pPass);
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiLogin(pEmail, pPass);
      onLoginSuccess(data.token, data.user);
    } catch (err: any) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const personas = [
    {
      role: 'ADMIN',
      name: 'Security Administrator',
      email: 'admin@trustvault.local',
      pass: 'Admin@TrustVault2026!',
      badgeClass: 'role-ADMIN',
      desc: 'Audit ledger oversight, user governance, 0 document access without explicit grant.'
    },
    {
      role: 'OWNER',
      name: 'Alice (Document Owner)',
      email: 'owner@trustvault.local',
      pass: 'Owner@TrustVault2026!',
      badgeClass: 'role-OWNER',
      desc: 'Sole authorized granter for her documents; uploads and manages access delegations.'
    },
    {
      role: 'VIEWER',
      name: 'Bob (Authorized Viewer)',
      email: 'viewer@trustvault.local',
      pass: 'Viewer@TrustVault2026!',
      badgeClass: 'role-VIEWER',
      desc: 'Granted READ permission on Doc 1 (MSA). Zero upload rights. Rejects mutations.'
    },
    {
      role: 'VIEWER',
      name: 'Eve (Untrusted Adversary)',
      email: 'eve@trustvault.local',
      pass: 'Eve@TrustVault2026!',
      badgeClass: 'role-VIEWER',
      desc: 'Zero grants across all documents. IDOR probes return 404 Information Barrier.'
    }
  ];

  return (
    <div
      style={{
        minHeight: '100vh',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '32px 16px',
        background: 'var(--bg-app)'
      }}
    >
      {/* Brand Header */}
      <div style={{ textAlign: 'center', marginBottom: '24px' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '42px',
            height: '42px',
            background: 'var(--color-primary-subtle)',
            border: '1px solid var(--color-primary-border)',
            borderRadius: 'var(--radius-sm)',
            color: '#60a5fa',
            marginBottom: '10px'
          }}
        >
          <Shield size={22} />
        </div>
        <h1 style={{ fontSize: '18px', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)' }}>
          TrustVault Enterprise Security Console
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '12px', marginTop: '2px' }}>
          Zero-Trust Access Control & Tamper-Evident HMAC-SHA256 Audit Ledger
        </p>
      </div>

      {/* Main Authentication Box */}
      <div
        style={{
          width: '100%',
          maxWidth: '400px',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-md)',
          padding: '24px',
          boxShadow: 'var(--shadow-elevation)',
          marginBottom: '24px'
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            paddingBottom: '12px',
            marginBottom: '16px',
            borderBottom: '1px solid var(--border-subtle)',
            fontSize: '12px',
            color: 'var(--text-secondary)'
          }}
        >
          <Lock size={13} color="var(--color-emerald)" />
          <span>PostgreSQL-Backed Identity Verification</span>
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
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              marginBottom: '14px'
            }}
          >
            <AlertCircle size={14} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Corporate Email</label>
            <div style={{ position: 'relative' }}>
              <input
                type="email"
                required
                placeholder="name@trustvault.local"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="username"
              />
            </div>
          </div>

          <div className="form-group">
            <label>Master Password</label>
            <input
              type="password"
              required
              placeholder="••••••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            disabled={isLoading}
            style={{ width: '100%', marginTop: '8px', padding: '8px' }}
          >
            {isLoading ? 'Verifying Credentials...' : 'Authenticate & Enter Vault'}
            <ArrowRight size={14} />
          </button>
        </form>
      </div>

      {/* Evaluation Principals Fast Selection */}
      <div style={{ width: '100%', maxWidth: '780px' }}>
        <div
          style={{
            fontSize: '11px',
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
            color: 'var(--text-muted)',
            marginBottom: '10px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between'
          }}
        >
          <span>Evaluation Principals (1-Click Test Harness)</span>
          <span style={{ fontFamily: 'var(--font-mono)' }}>Timing-Attack Safe Bcrypt (12 Rounds)</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px' }}>
          {personas.map((p) => (
            <div
              key={p.email}
              onClick={() => handleQuickPersona(p.email, p.pass)}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px',
                cursor: 'pointer',
                transition: 'all 0.12s ease'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = 'var(--border-strong)';
                e.currentTarget.style.background = 'var(--bg-surface-raised)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = 'var(--border-default)';
                e.currentTarget.style.background = 'var(--bg-surface)';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>{p.name.split(' ')[0]}</span>
                <span className={`role-pill ${p.badgeClass}`}>{p.role}</span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', marginBottom: '6px' }}>
                {p.email}
              </div>
              <p style={{ fontSize: '11px', color: 'var(--text-dim)', lineHeight: 1.4 }}>
                {p.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
