import React from 'react';

interface TrustValtLogoProps {
  size?: number;
  className?: string;
  glow?: boolean;
}

export const TrustValtLogo: React.FC<TrustValtLogoProps> = ({
  size = 32,
  className = '',
  glow = true
}) => {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 32 32"
      width={size}
      height={size}
      fill="none"
      className={className}
      style={{ display: 'inline-block', verticalAlign: 'middle', flexShrink: 0 }}
      aria-label="TrustValt Logo"
    >
      <defs>
        <linearGradient id="tv-logo-shield" x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#3b82f6" />
          <stop offset="50%" stopColor="#2563eb" />
          <stop offset="100%" stopColor="#1d4ed8" />
        </linearGradient>
        <linearGradient id="tv-logo-inner" x1="8" y1="6" x2="24" y2="26" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#0a101d" />
          <stop offset="100%" stopColor="#030712" />
        </linearGradient>
        <linearGradient id="tv-logo-v" x1="16" y1="8" x2="16" y2="23" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#38bdf8" />
          <stop offset="100%" stopColor="#2563eb" />
        </linearGradient>
        {glow && (
          <filter id="tv-logo-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feDropShadow dx="0" dy="1" stdDeviation="1.5" floodColor="#2563eb" floodOpacity="0.5" />
          </filter>
        )}
      </defs>

      {/* Outer Protective Shield */}
      <path
        d="M 16 2 L 28 6.5 V 15 C 28 22.8 22.8 28.8 16 30.5 C 9.2 28.8 4 22.8 4 15 V 6.5 Z"
        fill="url(#tv-logo-shield)"
        filter={glow ? 'url(#tv-logo-glow)' : undefined}
      />

      {/* Shield Inset Dark Mirror */}
      <path
        d="M 16 3.6 L 26.5 7.6 V 15 C 26.5 21.8 21.9 27.2 16 28.8 C 10.1 27.2 5.5 21.8 5.5 15 V 7.6 Z"
        fill="url(#tv-logo-inner)"
        stroke="#60a5fa"
        strokeWidth="0.8"
      />

      {/* TrustValt 'V' Geometric Monogram & Vault Gateway */}
      <path
        d="M 9.5 9.5 L 16 22.5 L 22.5 9.5 H 19.5 L 16 16.8 L 12.5 9.5 Z"
        fill="url(#tv-logo-v)"
      />

      {/* Vault Keyhole Core within 'V' */}
      <circle
        cx="16"
        cy="12"
        r="2.6"
        fill="#0a101d"
        stroke="#38bdf8"
        strokeWidth="0.9"
      />
      <path
        d="M 15.3 11.6 C 15.3 11.2 15.6 10.9 16 10.9 C 16.4 10.9 16.7 11.2 16.7 11.6 C 16.7 11.9 16.5 12.1 16.3 12.3 L 16.5 14.2 H 15.5 L 15.7 12.3 C 15.5 12.1 15.3 11.9 15.3 11.6 Z"
        fill="#ffffff"
      />

      {/* Emerald Verification Node at Base */}
      <circle
        cx="16"
        cy="25.5"
        r="1.2"
        fill="#10b981"
      />
    </svg>
  );
};

// Backward-compatible alias
export const TrustVaultLogo = TrustValtLogo;
