import React from 'react';
import { Shield, LogOut, User as UserIcon, Server, Database, KeyRound } from 'lucide-react';
import type { User } from '../types';

interface NavbarProps {
  user: User;
  onLogout: () => void;
  onSwitchPersona: (email: string) => void;
  onOpenMfa: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ user, onLogout, onSwitchPersona, onOpenMfa }) => {
  return (
    <>
      {/* Enterprise System Context Header */}
      <div className="system-status-bar">
        <div className="system-status-indicators">
          <span className="system-status-item">
            <Server size={12} />
            <span>Node.js v20 · Port 7777 (Loopback Ingress)</span>
          </span>
          <span className="system-status-item">
            <Database size={12} />
            <span>PostgreSQL 18 Dual-Role (REVOKE + DML Trigger Active)</span>
          </span>
          <span className="system-status-item">
            <span className="status-dot active"></span>
            <span style={{ color: 'var(--color-emerald)' }}>HMAC-SHA256 Ledger Synchronized</span>
          </span>
        </div>
        <div style={{ color: 'var(--text-dim)', fontFamily: 'var(--font-mono)' }}>
          RFC-Zero-Trust Compliant
        </div>
      </div>

      {/* Main Enterprise Navigation Bar */}
      <header className="navbar">
        <div className="brand">
          <div className="brand-icon">
            <Shield size={16} />
          </div>
          <div className="brand-title">
            <span>TrustVault</span>
            <span className="brand-badge">SECURE CONSOLE</span>
          </div>
        </div>

        <div className="principal-bar">
          {/* Principal / Persona Switcher for Evaluation */}
          <div className="persona-selector">
            <span className="persona-label">
              <KeyRound size={11} style={{ verticalAlign: 'middle', marginRight: '3px' }} />
              Test Principal:
            </span>
            <button
              className={`persona-btn ${user.email === 'admin@trustvault.local' ? 'active' : ''}`}
              onClick={() => onSwitchPersona('admin@trustvault.local')}
              title="Audit Oversight & Role Governance"
            >
              Admin
            </button>
            <button
              className={`persona-btn ${user.email === 'owner@trustvault.local' ? 'active' : ''}`}
              onClick={() => onSwitchPersona('owner@trustvault.local')}
              title="Alice: Uploads, Access Delegation, Document Owner"
            >
              Alice (Owner)
            </button>
            <button
              className={`persona-btn ${user.email === 'viewer@trustvault.local' ? 'active' : ''}`}
              onClick={() => onSwitchPersona('viewer@trustvault.local')}
              title="Bob: Authorized Reader for Master Services Agreement"
            >
              Bob (Viewer)
            </button>
            <button
              className={`persona-btn persona-eve ${user.email === 'eve@trustvault.local' ? 'active' : ''}`}
              onClick={() => onSwitchPersona('eve@trustvault.local')}
              title="Eve: Adversary with Zero Grants (Verifies 404 Information Barrier)"
            >
              Eve (Adversary)
            </button>
          </div>

          {/* Active Session Identity */}
          <div className="user-profile-badge">
            <UserIcon size={14} color="var(--text-secondary)" />
            <span style={{ fontWeight: 500 }}>{user.name}</span>
            <span className={`role-pill role-${user.role}`}>{user.role}</span>
          </div>

          <button
            className="btn btn-secondary btn-sm"
            onClick={onOpenMfa}
            title="Configure Two-Factor Authentication (TOTP)"
            style={{ display: 'flex', alignItems: 'center', gap: '4px' }}
          >
            <KeyRound size={13} color="var(--color-primary)" />
            <span>2FA</span>
          </button>

          <button
            className="btn btn-secondary btn-sm"
            onClick={onLogout}
            title="Terminate Active Session"
          >
            <LogOut size={13} />
            <span>Sign Out</span>
          </button>
        </div>
      </header>
    </>
  );
};
