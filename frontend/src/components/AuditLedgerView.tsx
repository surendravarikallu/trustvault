import React, { useState, useEffect } from 'react';
import { ShieldCheck, ShieldAlert, RefreshCw } from 'lucide-react';
import type { AuditRecord, AuditVerification } from '../types';
import { fetchAuditLogs, verifyAuditLedger } from '../api';

interface AuditLedgerViewProps {
  token: string;
}

export const AuditLedgerView: React.FC<AuditLedgerViewProps> = ({ token }) => {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [verification, setVerification] = useState<AuditVerification | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);

  useEffect(() => {
    loadAuditData();
  }, [selectedAction]);

  const loadAuditData = async () => {
    setIsLoading(true);
    try {
      const [logsData, verifyData] = await Promise.all([
        fetchAuditLogs(token, selectedAction ? { action: selectedAction } : undefined),
        verifyAuditLedger(token)
      ]);
      setLogs(logsData.logs || []);
      setVerification(verifyData);
    } catch (err: any) {
      console.error('Failed to load audit data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleManualVerify = async () => {
    setIsVerifying(true);
    try {
      const verifyData = await verifyAuditLedger(token);
      setVerification(verifyData);
    } catch (err: any) {
      console.error('Verification error:', err);
    } finally {
      setIsVerifying(false);
    }
  };

  const actions = [
    { label: 'All Actions', value: '' },
    { label: 'Security Denials', value: 'ACCESS_DENIED' },
    { label: 'Downloads', value: 'DOCUMENT_DOWNLOAD_STARTED' },
    { label: 'Uploads', value: 'DOCUMENT_UPLOADED' },
    { label: 'Grants', value: 'PERMISSION_GRANTED' },
    { label: 'Revocations', value: 'PERMISSION_REVOKED' },
    { label: 'Role Changes', value: 'USER_ROLE_CHANGED' }
  ];

  return (
    <div>
      {/* Cryptographic Ledger Health Banner */}
      {verification && (
        <div className={`audit-health-card ${verification.valid ? 'audit-health-verified' : 'audit-health-tampered'}`}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: 'var(--radius-sm)',
                background: verification.valid ? 'rgba(16, 185, 129, 0.15)' : 'rgba(244, 63, 94, 0.2)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                color: verification.valid ? 'var(--accent-emerald)' : 'var(--accent-rose)'
              }}
            >
              {verification.valid ? <ShieldCheck size={26} /> : <ShieldAlert size={26} />}
            </div>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <h3 style={{ fontSize: '1.1rem' }}>
                  {verification.valid ? 'HMAC-SHA256 Cryptographic Chain Verified' : 'CRITICAL: Ledger Integrity Violation!'}
                </h3>
                <span className={`status-pill ${verification.valid ? 'status-SUCCESS' : 'status-DENIED'}`}>
                  {verification.valid ? 'Active Ledger Validated' : 'TAMPERING DETECTED'}
                </span>
              </div>

              <div style={{ fontSize: '0.825rem', color: 'var(--text-muted)', marginTop: '4px' }}>
                {verification.valid ? (
                  <span>
                    Continuous HMAC link from Sequence 1 to Head • Verified against external anchor{' '}
                    <span className="mono">storage/audit_anchor.json</span> (Tail-truncation protection active)
                  </span>
                ) : (
                  <span style={{ color: 'var(--accent-rose)' }}>{verification.error}</span>
                )}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Head Sequence</div>
              <div className="mono" style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--accent-emerald)' }}>
                #{verification.headSequence || logs.length}
              </div>
            </div>

            <button
              className="btn btn-secondary btn-sm"
              onClick={handleManualVerify}
              disabled={isVerifying}
              title="Recalculates SHA256 hashes across all rows"
            >
              <RefreshCw size={14} className={isVerifying ? 'spin' : ''} />
              <span>{isVerifying ? 'Checking...' : 'Verify Ledger'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Action Filter Toolbar */}
      <div className="toolbar">
        <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
          {actions.map((act) => (
            <button
              key={act.value}
              className={`btn btn-sm ${selectedAction === act.value ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setSelectedAction(act.value)}
            >
              {act.label}
            </button>
          ))}
        </div>
      </div>

      {/* Audit Logs Table */}
      <div className="table-container">
        {isLoading ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            Inspecting cryptographic ledger rows...
          </div>
        ) : logs.length === 0 ? (
          <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
            No audit records found matching this filter.
          </div>
        ) : (
          <table>
            <thead>
              <tr>
                <th>Seq #</th>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Status</th>
                <th>Actor</th>
                <th>Target Document</th>
                <th>IP / Origin</th>
                <th>Details & Hash</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((record) => (
                <tr key={record.id}>
                  <td className="mono" style={{ fontWeight: 600, color: 'var(--accent-emerald)' }}>
                    #{record.sequenceNumber}
                  </td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>
                    {new Date(record.timestamp).toLocaleTimeString()}
                  </td>
                  <td>
                    <span className="mono" style={{ fontWeight: 600, fontSize: '0.75rem', color: 'var(--text-primary)' }}>
                      {record.action}
                    </span>
                  </td>
                  <td>
                    <span className={`status-pill status-${record.status}`}>{record.status}</span>
                  </td>
                  <td>
                    <div style={{ fontSize: '0.825rem' }}>{record.userEmail || 'System / Public'}</div>
                  </td>
                  <td>
                    <div style={{ fontSize: '0.825rem' }}>{record.documentTitle || record.documentId || '—'}</div>
                  </td>
                  <td className="mono" style={{ fontSize: '0.75rem' }}>
                    {record.ipAddress}
                  </td>
                  <td>
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>{record.details}</div>
                    <div className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }} title={record.hash}>
                      hash: {record.hash.substring(0, 16)}...
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
