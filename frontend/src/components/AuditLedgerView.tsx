import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  ShieldAlert,
  RefreshCw,
  Lock,
  Copy,
  Check,
  Hash,
  Database,
  User,
  FileText,
  UserX,
  UserCheck,
  Info,
  ChevronDown,
  ChevronRight,
  ShieldBan,
  ArrowRight
} from 'lucide-react';
import type { AuditRecord, AuditVerification } from '../types';
import { fetchAuditLogs, verifyAuditLedger } from '../api';

interface AuditLedgerViewProps {}

export const AuditLedgerView: React.FC<AuditLedgerViewProps> = () => {
  const [logs, setLogs] = useState<AuditRecord[]>([]);
  const [verification, setVerification] = useState<AuditVerification | null>(null);
  const [selectedAction, setSelectedAction] = useState<string>('');
  const [isLoading, setIsLoading] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);

  useEffect(() => {
    loadAuditData();
  }, [selectedAction]);

  const loadAuditData = async () => {
    setIsLoading(true);
    try {
      const [logsData, verifyData] = await Promise.all([
        fetchAuditLogs(selectedAction ? { action: selectedAction } : undefined),
        verifyAuditLedger()
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
      const verifyData = await verifyAuditLedger();
      setVerification(verifyData);
    } catch (err: any) {
      console.error('Verification error:', err);
    } finally {
      setIsVerifying(false);
    }
  };

  const copyHash = (hashVal: string) => {
    navigator.clipboard.writeText(hashVal);
    setCopiedHash(hashVal);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const formatCleanName = (email: string): string => {
    const prefix = email.split('@')[0];
    if (/^concurrent[_-]?(\d+)$/i.test(prefix)) {
      const num = prefix.match(/^concurrent[_-]?(\d+)$/i)![1];
      return `Concurrent Test Auditor ${num}`;
    }
    if (/^user(\d+)$/i.test(prefix)) {
      const num = prefix.match(/^user(\d+)$/i)![1];
      return `Automated Test Agent ${num}`;
    }
    if (prefix === 'audit_test') return 'HMAC Integrity Verifier';
    if (prefix.startsWith('demote_test')) return 'Demoted Test Candidate';
    return prefix
      .split(/[._-]/)
      .filter(Boolean)
      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
      .join(' ');
  };

  /**
   * Translates raw audit records into human-readable enterprise security narratives
   */
  const formatAuditStory = (log: AuditRecord) => {
    const displayName = log.userName || (log.userEmail ? formatCleanName(log.userEmail) : 'System Principal');
    const actor = log.userEmail
      ? `${displayName} (${log.userEmail})`
      : displayName;
    const doc = log.documentTitle || (log.documentId ? `Document(${log.documentId.substring(0, 8)})` : null);

    switch (log.action) {
      case 'USER_DEACTIVATED': {
        const targetMatch = log.details.match(/account (.*?)\./);
        const targetEmail = targetMatch ? targetMatch[1] : 'Target User';
        return {
          title: 'User Account Deactivated',
          icon: <UserX size={14} color="var(--color-rose)" />,
          description: (
            <span>
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> deactivated user{' '}
              <span className="mono-cell" style={{ color: '#fca5a5' }}>{targetEmail}</span>. Active sessions invalidated immediately.
            </span>
          ),
          subject: targetEmail,
          category: 'Identity Governance'
        };
      }

      case 'USER_ROLE_CHANGED': {
        return {
          title: 'User Role Modified',
          icon: <UserCheck size={14} color="var(--color-amber)" />,
          description: (
            <span>
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> updated user role: {log.details}
            </span>
          ),
          subject: 'Role Update',
          category: 'Identity Governance'
        };
      }

      case 'DOCUMENT_DOWNLOAD_STARTED': {
        return {
          title: 'Secure Document Downloaded',
          icon: <FileText size={14} color="#60a5fa" />,
          description: (
            <span>
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> downloaded file{' '}
              <strong style={{ color: '#93c5fd' }}>{doc || 'Protected Document'}</strong>.
            </span>
          ),
          subject: doc || 'File Download',
          category: 'Data Access'
        };
      }

      case 'DOCUMENT_UPLOADED': {
        return {
          title: 'Document Uploaded & Hashed',
          icon: <FileText size={14} color="var(--color-emerald)" />,
          description: (
            <span>
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> uploaded new vault document{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{doc || 'New Document'}</strong>.
            </span>
          ),
          subject: doc || 'Upload',
          category: 'Data Creation'
        };
      }

      case 'PERMISSION_GRANTED': {
        return {
          title: 'Access Permission Delegated',
          icon: <ShieldCheck size={14} color="var(--color-emerald)" />,
          description: (
            <span>
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> granted access on{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{doc}</strong>: {log.details}
            </span>
          ),
          subject: doc || 'Grant',
          category: 'Access Delegation'
        };
      }

      case 'PERMISSION_REVOKED': {
        return {
          title: 'Access Permission Revoked',
          icon: <ShieldAlert size={14} color="var(--color-rose)" />,
          description: (
            <span>
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> revoked permission on{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{doc}</strong> ({log.details}).
            </span>
          ),
          subject: doc || 'Revocation',
          category: 'Access Delegation'
        };
      }

      case 'ACCESS_DENIED': {
        return {
          title: 'Access Denied / IDOR Blocked',
          icon: <ShieldBan size={14} color="var(--color-rose)" />,
          description: (
            <span>
              Security Gatekeeper <strong style={{ color: 'var(--color-rose)' }}>BLOCKED</strong> probe by{' '}
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> on {doc || 'Resource'}. ({log.details})
            </span>
          ),
          subject: doc || 'Access Probe',
          category: 'Security Defense'
        };
      }

      case 'DOCUMENT_METADATA_READ': {
        return {
          title: 'Metadata Inspected',
          icon: <Info size={14} color="var(--text-dim)" />,
          description: (
            <span>
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> inspected metadata for{' '}
              <strong>{doc}</strong>.
            </span>
          ),
          subject: doc || 'Metadata',
          category: 'Telemetry'
        };
      }

      default: {
        return {
          title: log.action.replace(/_/g, ' '),
          icon: <Info size={14} color="var(--text-secondary)" />,
          description: (
            <span>
              <strong style={{ color: 'var(--text-primary)' }}>{actor}</strong> triggered {log.action}: {log.details}
            </span>
          ),
          subject: doc || 'System Event',
          category: 'General'
        };
      }
    }
  };

  const actions = [
    { label: 'All Events', value: '' },
    { label: 'Security Denials (403/404)', value: 'ACCESS_DENIED' },
    { label: 'Downloads', value: 'DOCUMENT_DOWNLOAD_STARTED' },
    { label: 'Uploads', value: 'DOCUMENT_UPLOADED' },
    { label: 'Grants', value: 'PERMISSION_GRANTED' },
    { label: 'Revocations', value: 'PERMISSION_REVOKED' },
    { label: 'Role Changes', value: 'USER_ROLE_CHANGED' }
  ];

  return (
    <div>
      {/* Top 4 Metrics Summary Grid */}
      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-label">Cryptographic Integrity</div>
          <div className="metric-value">
            {verification?.valid ? (
              <span style={{ color: 'var(--color-emerald)', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <ShieldCheck size={20} />
                <span>Chain Verified</span>
              </span>
            ) : (
              <span style={{ color: 'var(--color-rose)', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <ShieldAlert size={20} />
                <span>Tampering Detected</span>
              </span>
            )}
          </div>
          <div className="metric-meta">
            HMAC-SHA256 (13 columns hashed)
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">Monotonic Sequence Height</div>
          <div className="metric-value">
            <Hash size={20} color="var(--color-indigo)" />
            <span>#{verification?.totalRecords ?? logs.length}</span>
          </div>
          <div className="metric-meta">
            Advisory Lock: pg_advisory_xact_lock
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">External Disk Anchor</div>
          <div className="metric-value">
            <Lock size={20} color="var(--color-emerald)" />
            <span style={{ fontSize: '15px' }}>storage/audit_anchor.json</span>
          </div>
          <div className="metric-meta">
            {verification?.anchorMatched ? 'Anchor Matched Head' : 'Tail-truncation protection active'}
          </div>
        </div>

        <div className="metric-card">
          <div className="metric-label">Database Immutability</div>
          <div className="metric-value">
            <Database size={20} color="#60a5fa" />
            <span style={{ fontSize: '15px' }}>PostgreSQL 18 Trigger</span>
          </div>
          <div className="metric-meta">
            REVOKE UPDATE, DELETE ON AuditLog
          </div>
        </div>
      </div>

      {/* Toolbar & Action Filters */}
      <div className="toolbar-panel">
        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', alignItems: 'center' }}>
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-dim)', textTransform: 'uppercase', marginRight: '6px' }}>
            Filter Event Type:
          </span>
          {actions.map((act) => (
            <button
              key={act.value}
              className={`btn btn-xs ${selectedAction === act.value ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => setSelectedAction(act.value)}
            >
              {act.label}
            </button>
          ))}
        </div>

        <button
          className="btn btn-secondary btn-sm"
          onClick={handleManualVerify}
          disabled={isVerifying || isLoading}
          title="Recalculates cryptographic HMAC chain from Seq 1 to Head"
        >
          <RefreshCw size={13} className={isVerifying ? 'spin-icon' : ''} />
          <span>{isVerifying ? 'Verifying Chain...' : 'Recalculate Verification'}</span>
        </button>
      </div>

      {/* High-Clarity Enterprise Audit Log Table */}
      <div className="data-table-wrapper">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: '40px' }}></th>
              <th style={{ width: '60px' }}>Seq #</th>
              <th style={{ width: '100px' }}>Timestamp</th>
              <th style={{ width: '130px' }}>Action & Status</th>
              <th>Event Narrative (Who, What, Outcome)</th>
              <th style={{ width: '170px' }}>Principal & Target</th>
              <th style={{ width: '170px' }}>Cryptographic Link</th>
            </tr>
          </thead>
          <tbody>
            {logs.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: 'var(--text-muted)' }}>
                  {isLoading ? 'Querying HMAC ledger...' : 'No audit events recorded under active filter.'}
                </td>
              </tr>
            ) : (
              logs.map((log) => {
                const story = formatAuditStory(log);
                const isExpanded = expandedLogId === log.id;

                let badgeClass = 'status-SUCCESS';
                if (log.action === 'ACCESS_DENIED') badgeClass = 'status-DENIED';
                if (log.action === 'USER_ROLE_CHANGED') badgeClass = 'status-FAILED';
                if (log.action === 'USER_DEACTIVATED') badgeClass = 'status-DENIED';

                return (
                  <React.Fragment key={log.id}>
                    <tr
                      style={{ cursor: 'pointer' }}
                      onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                    >
                      <td>
                        {isExpanded ? (
                          <ChevronDown size={14} color="var(--text-secondary)" />
                        ) : (
                          <ChevronRight size={14} color="var(--text-dim)" />
                        )}
                      </td>

                      <td className="mono-cell" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                        #{log.sequenceNumber}
                      </td>

                      <td className="mono-cell" style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                        {new Date(log.timestamp).toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>

                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
                          <span className={`status-pill ${badgeClass}`} style={{ width: 'fit-content' }}>
                            {log.action}
                          </span>
                        </div>
                      </td>

                      {/* Main Readable Event Narrative */}
                      <td>
                        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '8px' }}>
                          <div style={{ marginTop: '2px' }}>{story.icon}</div>
                          <div style={{ fontSize: '12px', lineHeight: 1.45 }}>
                            {story.description}
                          </div>
                        </div>
                      </td>

                      {/* Explicit Actor & Subject */}
                      <td>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                          <div style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                            <User size={11} color="var(--text-dim)" style={{ flexShrink: 0 }} />
                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                              {log.userName || (log.userEmail ? formatCleanName(log.userEmail) : 'System Principal')}
                            </span>
                          </div>
                          {log.userEmail && (
                            <div className="mono-cell" style={{ fontSize: '10px', color: 'var(--text-secondary)', paddingLeft: '15px' }}>
                              ({log.userEmail})
                            </div>
                          )}
                          {log.documentTitle && (
                            <div style={{ fontSize: '11px', display: 'flex', alignItems: 'center', gap: '4px', color: '#93c5fd', marginTop: '2px' }}>
                              <FileText size={11} style={{ flexShrink: 0 }} />
                              <span style={{ maxWidth: '140px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={log.documentTitle}>
                                {log.documentTitle}
                              </span>
                            </div>
                          )}
                        </div>
                      </td>

                      {/* Cryptographic Hash Chain Link */}
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                          <span
                            className="hash-pill"
                            style={{ fontSize: '10px', background: 'transparent', borderColor: 'var(--border-subtle)', color: 'var(--text-dim)' }}
                            title={`Previous HMAC: ${log.previousHash || 'GENESIS'}`}
                          >
                            {log.previousHash ? `${log.previousHash.substring(0, 5)}..` : 'GENESIS'}
                          </span>
                          <ArrowRight size={10} color="var(--text-dim)" />
                          <span
                            className="hash-pill"
                            style={{ fontSize: '10px' }}
                            title={`Current HMAC: ${log.hash}`}
                          >
                            {log.hash ? `${log.hash.substring(0, 6)}...` : 'N/A'}
                          </span>
                          {log.hash && (
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation();
                                copyHash(log.hash);
                              }}
                              style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-dim)', padding: '0 2px' }}
                              title="Copy Full 64-char HMAC"
                            >
                              {copiedHash === log.hash ? <Check size={11} color="var(--color-emerald)" /> : <Copy size={11} />}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>

                    {/* Detailed Row Expansion Drawer */}
                    {isExpanded && (
                      <tr style={{ background: 'var(--bg-surface-raised)', borderBottom: '1px solid var(--border-default)' }}>
                        <td colSpan={7} style={{ padding: '14px 20px' }}>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', fontSize: '11px' }}>
                            <div>
                              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                                Event Context & Audit Assertions
                              </div>
                              <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                <div><strong>Action Type:</strong> <span className="mono-cell">{log.action}</span></div>
                                <div><strong>Actor Principal:</strong> <span className="mono-cell">{log.userName ? `${log.userName} (${log.userEmail || 'N/A'})` : (log.userEmail || 'Unauthenticated')} ({log.userId || 'N/A'})</span></div>
                                <div><strong>Target Resource ID:</strong> <span className="mono-cell">{log.documentId || 'N/A'}</span></div>
                                <div><strong>Client IP Address:</strong> <span className="mono-cell">{log.ipAddress}</span></div>
                                <div><strong>HTTP User Agent:</strong> <span className="mono-cell">{log.userAgent}</span></div>
                              </div>
                            </div>

                            <div>
                              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                                Cryptographic Integrity Trace
                              </div>
                              <div style={{ color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                                <div><strong>Monotonic Sequence:</strong> #{log.sequenceNumber} (Locked via pg_advisory_xact_lock)</div>
                                <div><strong>Preceding HMAC:</strong> <span className="mono-cell">{log.previousHash || 'GENESIS (Seq 1)'}</span></div>
                                <div><strong>Current HMAC-SHA256:</strong> <span className="mono-cell" style={{ color: '#6ee7b7' }}>{log.hash}</span></div>
                                <div><strong>Raw Log Details:</strong> <span className="mono-cell" style={{ color: 'var(--text-primary)' }}>{log.details}</span></div>
                              </div>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
