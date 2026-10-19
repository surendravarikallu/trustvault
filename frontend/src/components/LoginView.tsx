import React, { useState } from 'react';
import { Shield, ArrowRight, Lock, AlertCircle, KeyRound, QrCode, Copy, CheckCircle2 } from 'lucide-react';
import { apiLogin, apiVerifyLoginMfa, apiConfirmEnrollMfa } from '../api';
import type { User } from '../types';

interface LoginViewProps {
  onLoginSuccess: (token: string, user: User) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // 2-Step Challenge State (when MFA is already enabled)
  const [mfaChallengeToken, setMfaChallengeToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');

  // Pre-Login / On-Demand Authenticator Registration State
  const [enrollMfaActive, setEnrollMfaActive] = useState(false);
  const [mfaEnrollData, setMfaEnrollData] = useState<{
    mfaEnrollToken: string;
    qrCode: string;
    secret: string;
  } | null>(null);
  const [enrollTotpCode, setEnrollTotpCode] = useState('');
  const [enrollBackupCodes, setEnrollBackupCodes] = useState<string[]>([]);
  const [postEnrollAuth, setPostEnrollAuth] = useState<{ token: string; user: User } | null>(null);
  const [copiedKey, setCopiedKey] = useState(false);
  const [copiedCodes, setCopiedCodes] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (enrollMfaActive) {
      await handleStartEnroll(email, password);
      return;
    }

    setIsLoading(true);
    setError(null);

    try {
      const data = await apiLogin(email, password, false);
      if (data.mfaRequired && data.mfaChallengeToken) {
        setMfaChallengeToken(data.mfaChallengeToken);
      } else if (data.token && data.user) {
        onLoginSuccess(data.token, data.user);
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleStartEnroll = async (targetEmail?: string, targetPassword?: string) => {
    const eMail = targetEmail || email;
    const pWord = targetPassword || password;
    if (!eMail || !pWord) {
      setError('Please provide corporate email and password to initiate authenticator registration.');
      return;
    }

    setIsLoading(true);
    setError(null);
    setMfaChallengeToken(null);
    try {
      const data = await apiLogin(eMail, pWord, true);
      if (data.mfaEnrollRequired && data.mfaEnrollToken && data.qrCode && data.secret) {
        setMfaEnrollData({
          mfaEnrollToken: data.mfaEnrollToken,
          qrCode: data.qrCode,
          secret: data.secret
        });
      } else if (data.mfaRequired && data.mfaChallengeToken) {
        setMfaChallengeToken(data.mfaChallengeToken);
      } else if (data.token && data.user) {
        onLoginSuccess(data.token, data.user);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to initiate authenticator registration.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleConfirmEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaEnrollData) return;
    setIsLoading(true);
    setError(null);

    try {
      const data = await apiConfirmEnrollMfa(mfaEnrollData.mfaEnrollToken, enrollTotpCode);
      setEnrollBackupCodes(data.backupCodes || []);
      setPostEnrollAuth({ token: data.token, user: data.user });
    } catch (err: any) {
      setError(err.message || 'Invalid 6-digit code. Please verify against Google / Microsoft Authenticator.');
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

  const handleQuickPersona = async (pEmail: string, pPass: string) => {
    setEmail(pEmail);
    setPassword(pPass);
    setError(null);
    setMfaChallengeToken(null);
    setMfaEnrollData(null);
    setPostEnrollAuth(null);

    if (enrollMfaActive) {
      await handleStartEnroll(pEmail, pPass);
      return;
    }

    setIsLoading(true);
    try {
      const data = await apiLogin(pEmail, pPass, false);
      if (data.mfaRequired && data.mfaChallengeToken) {
        setMfaChallengeToken(data.mfaChallengeToken);
      } else if (data.token && data.user) {
        onLoginSuccess(data.token, data.user);
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed.');
    } finally {
      setIsLoading(false);
    }
  };

  const copySecretKey = () => {
    if (mfaEnrollData?.secret) {
      navigator.clipboard.writeText(mfaEnrollData.secret);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(enrollBackupCodes.join('\n'));
    setCopiedCodes(true);
    setTimeout(() => setCopiedCodes(false), 2000);
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
          maxWidth: '440px',
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

        {/* 1. Post-Enrollment Backup Codes Display */}
        {postEnrollAuth ? (
          <div>
            <div style={{ textAlign: 'center', marginBottom: '16px' }}>
              <CheckCircle2 size={36} color="var(--color-emerald)" style={{ margin: '0 auto 8px' }} />
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Authenticator Registered Successfully!
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Save these 8 single-use emergency backup recovery codes. Keep them in a secure password manager.
              </p>
            </div>

            <div
              style={{
                background: 'var(--bg-app)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px',
                display: 'grid',
                gridTemplateColumns: 'repeat(2, 1fr)',
                gap: '8px',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                textAlign: 'center',
                marginBottom: '16px'
              }}
            >
              {enrollBackupCodes.map((code, idx) => (
                <div key={idx} style={{ color: 'var(--color-primary)' }}>{code}</div>
              ))}
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={copyBackupCodes}
                style={{ flex: 1 }}
              >
                <Copy size={13} />
                <span>{copiedCodes ? 'Copied!' : 'Copy Codes'}</span>
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => onLoginSuccess(postEnrollAuth.token, postEnrollAuth.user)}
                style={{ flex: 1 }}
              >
                Enter Vault as {postEnrollAuth.user.role}
              </button>
            </div>
          </div>
        ) : mfaEnrollData ? (
          /* 2. QR Code Authenticator Registration Screen */
          <form onSubmit={handleConfirmEnroll}>
            <div style={{ textAlign: 'center', marginBottom: '14px' }}>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: '36px',
                  height: '36px',
                  borderRadius: '50%',
                  background: 'var(--color-primary-subtle)',
                  color: '#60a5fa',
                  marginBottom: '8px'
                }}
              >
                <QrCode size={18} />
              </div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
                Register Google / Microsoft Authenticator
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Scan this QR code with Google Authenticator, Microsoft Authenticator, or Authy:
              </p>
            </div>

            <div style={{ textAlign: 'center', marginBottom: '14px' }}>
              <img
                src={mfaEnrollData.qrCode}
                alt="Authenticator QR Code"
                style={{
                  width: '180px',
                  height: '180px',
                  borderRadius: 'var(--radius-sm)',
                  border: '1px solid var(--border-default)',
                  background: '#ffffff',
                  padding: '8px',
                  display: 'inline-block'
                }}
              />
              <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' }}>
                Manual key: <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{mfaEnrollData.secret}</code>
                <button
                  type="button"
                  onClick={copySecretKey}
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--color-primary)',
                    cursor: 'pointer',
                    fontSize: '11px',
                    marginLeft: '6px'
                  }}
                >
                  {copiedKey ? 'Copied' : 'Copy'}
                </button>
              </div>
            </div>

            <div className="form-group">
              <label>Enter 6-Digit Code from Authenticator App</label>
              <input
                type="text"
                required
                autoFocus
                placeholder="000000"
                value={enrollTotpCode}
                onChange={(e) => setEnrollTotpCode(e.target.value.trim())}
                style={{ textAlign: 'center', letterSpacing: '0.2em', fontSize: '16px', fontFamily: 'var(--font-mono)' }}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={isLoading || enrollTotpCode.length < 6}
              style={{ width: '100%', marginTop: '8px', padding: '8px' }}
            >
              {isLoading ? 'Verifying Code...' : 'Activate Authenticator & Enter Vault'}
              <ArrowRight size={14} />
            </button>

            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setMfaEnrollData(null);
                setEnrollTotpCode('');
                setError(null);
              }}
              style={{ width: '100%', marginTop: '8px', padding: '8px' }}
            >
              Cancel
            </button>
          </form>
        ) : mfaChallengeToken ? (
          /* 3. Two-Step Login Challenge (when MFA is active on account) */
          <form onSubmit={handleMfaChallengeSubmit}>
            <div style={{ textAlign: 'center', marginBottom: '16px' }}>
              <div
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: '38px',
                  height: '38px',
                  borderRadius: '50%',
                  background: 'var(--color-primary-subtle)',
                  color: '#60a5fa',
                  marginBottom: '8px'
                }}
              >
                <KeyRound size={20} />
              </div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>Two-Factor Challenge</h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                Enter the 6-digit TOTP code from Google / Microsoft Authenticator, or an emergency recovery backup code.
              </p>
            </div>

            <div className="form-group">
              <label>Verification / Backup Code</label>
              <input
                type="text"
                required
                autoFocus
                placeholder="000000 or BACKUP-CODE"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.trim())}
                style={{ textAlign: 'center', letterSpacing: '0.15em', fontSize: '16px', fontFamily: 'var(--font-mono)' }}
              />
            </div>

            <button
              type="submit"
              className="btn btn-primary"
              disabled={isLoading || totpCode.length < 6}
              style={{ width: '100%', marginTop: '8px', padding: '8px' }}
            >
              {isLoading ? 'Verifying Code...' : 'Confirm Identity & Enter Vault'}
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
              style={{ width: '100%', marginTop: '8px', padding: '8px' }}
            >
              Back to Password Login
            </button>
          </form>
        ) : (
          /* 4. Standard Password Login Form */
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

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', margin: '6px 0 14px' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', cursor: 'pointer', color: 'var(--text-secondary)' }}>
                <input
                  type="checkbox"
                  checked={enrollMfaActive}
                  onChange={(e) => setEnrollMfaActive(e.target.checked)}
                />
                <span>Register Authenticator (Show QR Code)</span>
              </label>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <button
                type="submit"
                className="btn btn-primary"
                disabled={isLoading}
                style={{ width: '100%', padding: '8px' }}
              >
                {isLoading ? 'Verifying Credentials...' : (enrollMfaActive ? 'Proceed to QR Code Enrollment' : 'Authenticate & Enter Vault')}
                <ArrowRight size={14} />
              </button>

              <button
                type="button"
                className="btn btn-secondary"
                disabled={isLoading}
                onClick={() => handleStartEnroll()}
                style={{ width: '100%', padding: '7px', fontSize: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px' }}
                title="Scan QR code with Google Authenticator or Microsoft Authenticator"
              >
                <QrCode size={13} color="var(--color-primary)" />
                <span>Enroll in Google / Microsoft Authenticator</span>
              </button>
            </div>
          </form>
        )}
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
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '8px'
          }}
        >
          <span>Evaluation Principals (1-Click Test Harness)</span>
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              cursor: 'pointer',
              color: enrollMfaActive ? 'var(--color-primary)' : 'var(--text-secondary)',
              fontSize: '11px',
              textTransform: 'none'
            }}
          >
            <input
              type="checkbox"
              checked={enrollMfaActive}
              onChange={(e) => setEnrollMfaActive(e.target.checked)}
              style={{ cursor: 'pointer' }}
            />
            <span style={{ fontWeight: enrollMfaActive ? 600 : 400 }}>
              Show Authenticator QR Code on Persona Click
            </span>
          </label>
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
