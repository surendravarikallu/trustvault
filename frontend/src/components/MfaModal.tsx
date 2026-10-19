import React, { useState } from 'react';
import { X, QrCode, CheckCircle2, AlertCircle, Copy, KeyRound } from 'lucide-react';
import { apiSetupMfa, apiVerifyMfaSetup, apiDisableMfa } from '../api';

interface MfaModalProps {
  token: string;
  isOpen: boolean;
  onClose: () => void;
  onMfaStatusChange?: () => void;
}

export const MfaModal: React.FC<MfaModalProps> = ({
  token,
  isOpen,
  onClose,
  onMfaStatusChange
}) => {
  const [step, setStep] = useState<'initial' | 'setup' | 'activated' | 'disable'>('initial');
  const [qrCode, setQrCode] = useState<string | null>(null);
  const [secret, setSecret] = useState<string | null>(null);
  const [verificationCode, setVerificationCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [disablePassword, setDisablePassword] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  if (!isOpen) return null;

  const handleStartSetup = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiSetupMfa(token);
      setQrCode(data.qrCode);
      setSecret(data.secret);
      setStep('setup');
    } catch (err: any) {
      setError(err.message || 'Failed to initiate MFA setup.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleConfirmSetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      const data = await apiVerifyMfaSetup(token, verificationCode);
      setBackupCodes(data.backupCodes || []);
      setStep('activated');
      if (onMfaStatusChange) onMfaStatusChange();
    } catch (err: any) {
      setError(err.message || 'Invalid verification code. Please check your authenticator app.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisableMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      await apiDisableMfa(token, disablePassword, disableCode);
      setStep('initial');
      if (onMfaStatusChange) onMfaStatusChange();
      onClose();
    } catch (err: any) {
      setError(err.message || 'Failed to disable MFA. Check password and TOTP code.');
    } finally {
      setIsLoading(false);
    }
  };

  const copyBackupCodes = () => {
    navigator.clipboard.writeText(backupCodes.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="modal-backdrop">
      <div className="modal-card" style={{ maxWidth: '460px' }}>
        <div className="modal-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <KeyRound size={16} color="var(--color-primary)" />
            <h2 style={{ fontSize: '15px', fontWeight: 600 }}>Multi-Factor Authentication (TOTP)</h2>
          </div>
          <button className="icon-btn" onClick={onClose}>
            <X size={16} />
          </button>
        </div>

        <div className="modal-body">
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

          {step === 'initial' && (
            <div>
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '16px' }}>
                Protect your account with RFC 6238 time-based one-time passwords (TOTP). Works with Google Authenticator, Authy, 1Password, or any standard authenticator app.
              </p>

              <div style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={handleStartSetup}
                  disabled={isLoading}
                  style={{ flex: 1 }}
                >
                  <QrCode size={14} />
                  <span>Configure Authenticator</span>
                </button>

                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setStep('disable')}
                >
                  Disable MFA
                </button>
              </div>
            </div>
          )}

          {step === 'setup' && (
            <div>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                1. Scan this QR code with your authenticator app:
              </p>

              {qrCode && (
                <div style={{ textAlign: 'center', margin: '12px 0' }}>
                  <img
                    src={qrCode}
                    alt="MFA QR Code"
                    style={{
                      width: '180px',
                      height: '180px',
                      borderRadius: 'var(--radius-sm)',
                      border: '1px solid var(--border-default)',
                      background: '#fff',
                      padding: '8px'
                    }}
                  />
                  {secret && (
                    <div style={{ marginTop: '8px', fontSize: '11px', color: 'var(--text-muted)' }}>
                      Manual key: <code style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{secret}</code>
                    </div>
                  )}
                </div>
              )}

              <form onSubmit={handleConfirmSetup} style={{ marginTop: '16px' }}>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '8px' }}>
                  2. Enter the 6-digit code shown in your app to activate:
                </p>
                <div className="form-group">
                  <input
                    type="text"
                    required
                    placeholder="000000"
                    value={verificationCode}
                    onChange={(e) => setVerificationCode(e.target.value.trim())}
                    style={{ textAlign: 'center', letterSpacing: '0.2em', fontSize: '16px', fontFamily: 'var(--font-mono)' }}
                  />
                </div>

                <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => setStep('initial')}
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="btn btn-primary"
                    disabled={isLoading || verificationCode.length < 6}
                    style={{ flex: 1 }}
                  >
                    {isLoading ? 'Verifying...' : 'Activate MFA'}
                  </button>
                </div>
              </form>
            </div>
          )}

          {step === 'activated' && (
            <div>
              <div style={{ textAlign: 'center', marginBottom: '16px' }}>
                <CheckCircle2 size={36} color="var(--color-emerald)" style={{ margin: '0 auto 8px' }} />
                <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>MFA Successfully Activated!</h3>
                <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                  Save these single-use recovery backup codes in a safe place. Each code can be used once if you lose your phone.
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
                {backupCodes.map((c, i) => (
                  <div key={i} style={{ color: 'var(--color-primary)' }}>{c}</div>
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
                  <span>{copied ? 'Copied!' : 'Copy Codes'}</span>
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={onClose}
                  style={{ flex: 1 }}
                >
                  Done
                </button>
              </div>
            </div>
          )}

          {step === 'disable' && (
            <form onSubmit={handleDisableMfa}>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginBottom: '12px' }}>
                Disabling MFA requires verifying both your account password and a valid 6-digit TOTP code.
              </p>

              <div className="form-group">
                <label>Master Password</label>
                <input
                  type="password"
                  required
                  placeholder="••••••••••••••••"
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label>Current 6-Digit TOTP Code</label>
                <input
                  type="text"
                  required
                  placeholder="000000"
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value.trim())}
                  style={{ textAlign: 'center', letterSpacing: '0.15em', fontFamily: 'var(--font-mono)' }}
                />
              </div>

              <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setStep('initial')}
                >
                  Back
                </button>
                <button
                  type="submit"
                  className="btn btn-danger"
                  disabled={isLoading}
                  style={{ flex: 1 }}
                >
                  {isLoading ? 'Deactivating...' : 'Confirm Disable MFA'}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
};
