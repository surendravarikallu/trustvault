import React from 'react';
import { LogOut, User as UserIcon, Server, Database, KeyRound } from 'lucide-react';
import { TrustVaultLogo } from './TrustVaultLogo';
import type { User } from '../types';

interface NavbarProps {
  user: User;
  onLogout: () => void;
  onSwitchPersona?: (email: string) => void;
  onOpenMfa: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ user, onLogout, onOpenMfa }) => {
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
          trustvalt.me · RFC-Zero-Trust Compliant
        </div>
      </div>

      {/* Main Enterprise Navigation Bar */}
      <header className="navbar">
        <div className="brand">
          <TrustVaultLogo size={24} />
          <div className="brand-title">
            <span>TrustValt</span>
            <span className="brand-badge">trustvalt.me</span>
          </div>
        </div>

        <div className="principal-bar">

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
