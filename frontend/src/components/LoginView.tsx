import React, { useState } from 'react';
import { Shield, ArrowRight } from 'lucide-react';
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
      setError(err.message);
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
      setError(err.message);
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
      desc: 'Audit verification, user role control, zero file access without grant.'
    },
    {
      role: 'OWNER',
      name: 'Alice (Document Owner)',
      email: 'owner@trustvault.local',
      pass: 'Owner@TrustVault2026!',
      desc: 'Can upload, grant/revoke permissions, and use AI reviewer suggestions.'
    },
    {
      role: 'VIEWER',
      name: 'Bob (Authorized Viewer)',
      email: 'viewer@trustvault.local',
      pass: 'Viewer@TrustVault2026!',
      desc: 'Has explicit READ grant to Doc 1 (MSA). Zero upload rights.'
    },
    {
      role: 'VIEWER',
      name: 'Eve (Adversary / Intruder)',
      email: 'eve@trustvault.local',
      pass: 'Eve@TrustVault2026!',
      desc: 'Zero document grants. Probes receive 404 (Information barrier active).'
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
        padding: '24px'
      }}
    >
      <div style={{ textAlign: 'center', marginBottom: '28px' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '48px',
            height: '48px',
            background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.2), rgba(99, 102, 241, 0.2))',
            border: '1px solid rgba(16, 185, 129, 0.4)',
            borderRadius: 'var(--radius-md)',
            color: 'var(--accent-emerald)',
            marginBottom: '12px'
          }}
        >
          <Shield size={24} />
        </div>
        <h1 style={{ fontSize: '1.75rem', marginBottom: '6px' }}>TrustVault</h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '0.9rem', maxWidth: '380px' }}>
          Zero-trust enterprise document engine with cryptographic audit ledger
        </p>
      </div>

      <div
        style={{
          width: '100%',
          maxWidth: '420px',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-subtle)',
          borderRadius: 'var(--radius-lg)',
          padding: '28px',
          boxShadow: 'var(--shadow-subtle)',
          marginBottom: '28px'
        }}
      >
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
                style={{ width: '100%' }}
              />
            </div>
          </div>

          <div className="form-group">
            <label>Master Password</label>
            <input
              type="password"
              required
              placeholder="••••••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={{ width: '100%' }}
            />
          </div>

          <button
            type="submit"
            className="btn btn-primary"
            style={{ width: '100%', justifyContent: 'center', marginTop: '12px' }}
            disabled={isLoading}
          >
            {isLoading ? 'Verifying Credentials...' : 'Sign In to Vault'}
          </button>
        </form>
      </div>

      {/* Evaluation Persona Fast-Switcher Cards */}
      <div style={{ width: '100%', maxWidth: '960px' }}>
        <div style={{ textAlign: 'center', marginBottom: '12px', fontSize: '0.8rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          Evaluation Seed Personas (Click to Login Instantly)
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
          {personas.map((p) => (
            <div
              key={p.email}
              onClick={() => handleQuickPersona(p.email, p.pass)}
              style={{
                background: 'var(--bg-card)',
                border: '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                padding: '14px',
                cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
              onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'rgba(16, 185, 129, 0.4)')}
              onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border-subtle)')}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                <span className={`role-tag role-${p.role}`}>{p.role}</span>
                <ArrowRight size={14} color="var(--text-muted)" />
              </div>
              <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{p.name}</div>
              <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--accent-emerald)', marginBottom: '6px' }}>
                {p.email}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', lineHeight: '1.4' }}>
                {p.desc}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
