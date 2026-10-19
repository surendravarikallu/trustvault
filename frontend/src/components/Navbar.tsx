import React from 'react';
import { Shield, LogOut, User as UserIcon } from 'lucide-react';
import type { User } from '../types';

interface NavbarProps {
  user: User;
  onLogout: () => void;
  onSwitchPersona: (email: string) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ user, onLogout, onSwitchPersona }) => {
  return (
    <header className="navbar">
      <div className="brand">
        <div className="brand-shield">
          <Shield size={18} />
        </div>
        <span>TrustVault</span>
        <div className="zero-trust-badge">
          <span className="pulse-dot"></span>
          <span>Zero-Trust Enforced</span>
        </div>
      </div>

      <div className="nav-user">
        {/* Quick persona switch bar for evaluation & live demonstration */}
        <div className="persona-switcher">
          <span style={{ color: 'var(--text-muted)' }}>Demo Switch:</span>
          <button
            className={`btn btn-sm ${user.email === 'admin@trustvault.local' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => onSwitchPersona('admin@trustvault.local')}
            title="Switch to Administrator"
          >
            Admin
          </button>
          <button
            className={`btn btn-sm ${user.email === 'owner@trustvault.local' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => onSwitchPersona('owner@trustvault.local')}
            title="Switch to Alice (Document Owner)"
          >
            Alice (Owner)
          </button>
          <button
            className={`btn btn-sm ${user.email === 'viewer@trustvault.local' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => onSwitchPersona('viewer@trustvault.local')}
            title="Switch to Bob (Authorized Viewer)"
          >
            Bob (Viewer)
          </button>
          <button
            className={`btn btn-sm ${user.email === 'eve@trustvault.local' ? 'btn-danger' : 'btn-secondary'}`}
            onClick={() => onSwitchPersona('eve@trustvault.local')}
            title="Switch to Eve (Unauthorized Adversary)"
          >
            Eve (Adversary)
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <UserIcon size={16} color="var(--text-secondary)" />
          <span style={{ fontSize: '0.875rem', fontWeight: 500 }}>{user.name}</span>
          <span className={`role-tag role-${user.role}`}>{user.role}</span>
        </div>

        <button className="btn btn-secondary btn-sm" onClick={onLogout} title="Invalidates active JWT">
          <LogOut size={14} />
          <span>Logout</span>
        </button>
      </div>
    </header>
  );
};
