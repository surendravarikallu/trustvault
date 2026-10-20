import React, { useState } from 'react';
import { ArrowRight, Lock, AlertCircle, KeyRound, Eye, EyeOff } from 'lucide-react';
import { TrustVaultLogo } from './TrustVaultLogo';
import { apiLogin, apiVerifyLoginMfa } from '../api';
import type { User } from '../types';

interface LoginViewProps {
  onLoginSuccess: (token: string, user: User) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const [usernameOrEmail, setUsernameOrEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 2-Step Challenge State (when 2FA is active on the account)
  const [mfaChallengeToken, setMfaChallengeToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      const data = await apiLogin(usernameOrEmail.trim(), password, false);
      if (data.mfaRequired && data.mfaChallengeToken) {
        setMfaChallengeToken(data.mfaChallengeToken);
      } else if (data.token && data.user) {
        onLoginSuccess(data.token, data.user);
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please verify your credentials.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleMfaChallengeSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaChallengeToken) return;
    setIsLoading(true);
    setError(null);

    try {
      const data = await apiVerifyLoginMfa(mfaChallengeToken, totpCode);
      onLoginSuccess(data.token, data.user);
    } catch (err: any) {
      setError(err.message || 'Invalid TOTP or recovery backup code.');
    } finally {
      setIsLoading(false);
    }
  };

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
      <div style={{ textAlign: 'center', marginBottom: '28px' }}>
        <div style={{ display: 'inline-flex', marginBottom: '14px' }}>
          <TrustVaultLogo size={48} />
        </div>
        <h1 style={{ fontFamily: 'var(--font-display)', fontSize: '22px', fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text-primary)', margin: 0 }}>
          TrustValt Enterprise Security Console
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '13px', marginTop: '6px' }}>
          Zero-Trust Access Control & Tamper-Evident HMAC-SHA256 Audit Ledger • trustvalt.me
        </p>
      </div>

      {/* Main Authentication Box */}
      <div
        style={{
          width: '100%',
          maxWidth: '420px',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border-default)',
          borderRadius: 'var(--radius-md)',
          padding: '28px',
          boxShadow: 'var(--shadow-elevation)'
        }}
      >
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            paddingBottom: '14px',
            marginBottom: '18px',
            borderBottom: '1px solid var(--border-subtle)',
            fontSize: '12px',
            color: 'var(--text-secondary)'
          }}
        >
          <Lock size={14} color="var(--color-emerald)" />
          <span>PostgreSQL Dual-Role Identity Ingress</span>
        </div>

        {error && (
          <div
            style={{
              background: 'var(--color-rose-subtle)',
              border: '1px solid var(--color-rose-border)',
              color: '#fca5a5',
              padding: '10px 14px',
              borderRadius: 'var(--radius-sm)',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              marginBottom: '18px'
            }}
          >
            <AlertCircle size={15} style={{ flexShrink: 0 }} />
            <span>{error}</span>
          </div>
        )}

        {mfaChallengeToken ? (
          /* Two-Step Login Challenge (when MFA is active on account) */
          <form onSubmit={handleMfaChallengeSubmit}>
            <div style={{ textAlign: 'center', marginBottom: '20px' }}>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: '42px',
                  height: '42px',
                  borderRadius: '50%',
                  background: 'var(--color-primary-subtle)',
                  color: '#60a5fa',
                  marginBottom: '10px'
                }}
              >
                <KeyRound size={20} />
              </div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0 }}>
                Two-Factor Security Challenge
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '6px', lineHeight: 1.4 }}>
                Enter the 6-digit TOTP code from your authenticator app (Google Authenticator, Microsoft Authenticator) or an emergency backup code.
              </p>
            </div>

            <div className="form-group" style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)' }}>
                Verification or Backup Code
              </label>
              <input
                type="text"
                required
                autoFocus
                placeholder="000000 or BACKUP-CODE"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.trim())}
                style={{
                  textAlign: 'center',
                  letterSpacing: '0.15em',
                  fontSize: '16px',
                  fontFamily: 'var(--font-mono)',
                  padding: '10px'
                }}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={isLoading || totpCode.length < 6}
              style={{ width: '100%', padding: '10px', fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
            >
              <span>{isLoading ? 'Verifying Code...' : 'Confirm Identity & Enter Vault'}</span>
              <ArrowRight size={14} />
            </button>

            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setMfaChallengeToken(null);
                setTotpCode('');
                setError(null);
              }}
              style={{ width: '100%', marginTop: '10px', padding: '9px', fontSize: '12px' }}
            >
              Back to Password Sign In
            </button>
          </form>
        ) : (
          /* Standard Corporate Password Login Form */
          <form onSubmit={handleSubmit}>
            <div className="form-group" style={{ marginBottom: '16px' }}>
              <label style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                Username or Corporate Email Address
              </label>
              <input
                type="text"
                required
                autoFocus
                placeholder="admin, owner, or user@trustvault.local"
                value={usernameOrEmail}
                onChange={(e) => setUsernameOrEmail(e.target.value)}
                autoComplete="username"
                style={{ padding: '10px', fontSize: '13px' }}
              />
            </div>

            <div className="form-group" style={{ marginBottom: '20px' }}>
              <label style={{ fontSize: '12px', fontWeight: 500, color: 'var(--text-secondary)', display: 'block', marginBottom: '6px' }}>
                Master Password
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  type={showPassword ? 'text' : 'password'}
                  required
                  placeholder="••••••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  style={{ padding: '10px 42px 10px 12px', fontSize: '13px', width: '100%' }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  aria-label={showPassword ? 'Hide password' : 'Show password'}
                  title={showPassword ? 'Hide password' : 'Show password'}
                  style={{
                    position: 'absolute',
                    right: '10px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'transparent',
                    border: 'none',
                    cursor: 'pointer',
                    color: 'var(--text-muted)',
                    display: 'flex',
                    alignItems: 'center',
                    padding: '4px'
                  }}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={isLoading}
              style={{ width: '100%', padding: '10px', fontSize: '13px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px' }}
            >
              <span>{isLoading ? 'Verifying Credentials...' : 'Authenticate & Enter Vault'}</span>
              <ArrowRight size={14} />
            </button>
          </form>
        )}
      </div>

      <div style={{ marginTop: '24px', fontSize: '11px', color: 'var(--text-dim)', textAlign: 'center' }}>
        Protected by Argon2id / Bcrypt-12 Password Hashing & RFC 6238 TOTP Validation
      </div>
    </div>
  );
};

export default LoginView;
