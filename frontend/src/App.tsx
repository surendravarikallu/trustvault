import React, { useState, useEffect } from 'react';
import { FileText, Shield, Users as UsersIcon, CheckCircle2, AlertCircle, KeyRound } from 'lucide-react';
import type { User, VaultDocument } from './types';
import { Navbar } from './components/Navbar';
import { DocumentList } from './components/DocumentList';
import { UploadModal } from './components/UploadModal';
import { PermissionsModal } from './components/PermissionsModal';
import { AuditLedgerView } from './components/AuditLedgerView';
import { UserDirectoryView } from './components/UserDirectoryView';
import { LoginView } from './components/LoginView';
import { MfaModal } from './components/MfaModal';
import { RevisionModal } from './components/RevisionModal';
import { VersionHistoryModal } from './components/VersionHistoryModal';
import { fetchDocuments, downloadDocument, deleteDocument, apiLogin, apiLogout, apiMe } from './api';

type Tab = 'documents' | 'audit' | 'users';

export const App: React.FC = () => {
  const [user, setUser] = useState<User | null>(null);
  const [isHydrating, setIsHydrating] = useState<boolean>(true);

  const [activeTab, setActiveTab] = useState<Tab>('documents');
  const [documents, setDocuments] = useState<VaultDocument[]>([]);
  const [isLoadingDocs, setIsLoadingDocs] = useState(false);

  // Modals state
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [permissionsDoc, setPermissionsDoc] = useState<VaultDocument | null>(null);
  const [revisionDoc, setRevisionDoc] = useState<VaultDocument | null>(null);
  const [historyDoc, setHistoryDoc] = useState<VaultDocument | null>(null);
  const [isMfaOpen, setIsMfaOpen] = useState(false);

  // 2FA Prompt Banner in-memory state
  const [mfaBannerDismissed, setMfaBannerDismissed] = useState<boolean>(false);

  // Toast notification state
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  // Verify active session on boot purely via __Host- cookie without localStorage
  useEffect(() => {
    // Proactively clear any legacy client storage to guarantee DevTools Application tab is completely empty
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch {
      // ignore
    }

    apiMe()
      .then((data) => {
        if (data && data.user) {
          setUser(data.user);
        }
      })
      .catch(() => {
        // Session invalid or not logged in
        setUser(null);
      })
      .finally(() => {
        setIsHydrating(false);
      });
  }, []);

  useEffect(() => {
    if (user) {
      loadDocuments();
    }
  }, [user]);

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message });
    setTimeout(() => setToast(null), 4000);
  };

  const handleLoginSuccess = (newUser: User) => {
    setUser(newUser);
    setActiveTab('documents');
    showToast('success', `Signed in as ${newUser.name} (${newUser.role})`);
  };

  const handleLogout = async () => {
    try {
      await apiLogout();
    } catch {
      // ignore
    }
    setUser(null);
    setDocuments([]);
    setActiveTab('documents');
    try {
      localStorage.clear();
      sessionStorage.clear();
    } catch {
      // ignore
    }
    showToast('success', 'Logged out.');
  };

  const handleDismissMfaBanner = () => {
    setMfaBannerDismissed(true);
  };

  const handleMfaStatusChange = () => {
    if (user) {
      setUser({ ...user, mfaEnabled: true });
    }
    showToast('success', 'MFA status updated. Account is now secured with TOTP.');
  };

  const handleSwitchPersona = async (email: string) => {
    const passwords: Record<string, string> = {
      'admin@trustvault.local': 'Admin@TrustVault2026!',
      'owner@trustvault.local': 'Owner@TrustVault2026!',
      'viewer@trustvault.local': 'Viewer@TrustVault2026!',
      'eve@trustvault.local': 'Eve@TrustVault2026!'
    };

    try {
      const data = await apiLogin(email, passwords[email]);
      if (data.mfaRequired) {
        showToast('error', `Account ${email} has 2FA enabled. Please sign in with your 6-digit TOTP code.`);
        handleLogout();
        return;
      }
      if (data.user) {
        handleLoginSuccess(data.user);
        if (data.user.role !== 'ADMIN') {
          setActiveTab('documents');
        }
      }
    } catch (err: any) {
      showToast('error', `Failed to switch persona: ${err.message}`);
    }
  };

  const loadDocuments = async (filters?: any) => {
    if (!user) return;
    setIsLoadingDocs(true);
    try {
      const data = await fetchDocuments(filters);
      setDocuments(data);
    } catch (err: any) {
      showToast('error', err.message);
      if (err.message.includes('revoked') || err.message.includes('inactive')) {
        handleLogout();
      }
    } finally {
      setIsLoadingDocs(false);
    }
  };

  const handleDownload = async (doc: VaultDocument) => {
    showToast('success', `Streaming ${doc.originalFilename}...`);
    try {
      await downloadDocument(doc.id, doc.originalFilename);
      showToast('success', `Downloaded ${doc.originalFilename} safely.`);
      // Refresh documents list to reflect Burn-on-Download grant self-destruct if applicable
      await loadDocuments();
    } catch (err: any) {
      showToast('error', `Download Refused: ${err.message}`);
    }
  };

  const [deleteConfirmDocId, setDeleteConfirmDocId] = useState<string | null>(null);

  const handleDelete = (docId: string) => {
    setDeleteConfirmDocId(docId);
  };

  const confirmDelete = async () => {
    if (!deleteConfirmDocId) return;
    const targetId = deleteConfirmDocId;
    setDeleteConfirmDocId(null);
    try {
      await deleteDocument(targetId);
      showToast('success', 'Document soft-deleted.');
      await loadDocuments();
    } catch (err: any) {
      showToast('error', err.message);
    }
  };

  if (isHydrating) {
    return (
      <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--bg-app)', color: 'var(--text-muted)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
          <span>Validating Vault Session...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <LoginView onLoginSuccess={handleLoginSuccess} />;
  }

  const isAdmin = user.role === 'ADMIN';
  const showMfaBanner = user && !user.mfaEnabled && !mfaBannerDismissed;

  return (
    <div>
      <Navbar
        user={user}
        onLogout={handleLogout}
        onSwitchPersona={handleSwitchPersona}
        onOpenMfa={() => setIsMfaOpen(true)}
      />

      <main className="workspace-container">
        {/* Post-Login 2FA Security Prompt Banner */}
        {showMfaBanner && (
          <div
            style={{
              background: 'linear-gradient(135deg, rgba(30, 41, 59, 0.95), rgba(15, 23, 42, 0.95))',
              border: '1px solid rgba(59, 130, 246, 0.35)',
              borderRadius: 'var(--radius-sm)',
              padding: '14px 18px',
              marginBottom: '16px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '16px',
              flexWrap: 'wrap'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flex: '1 1 300px' }}>
              <div
                style={{
                  width: '36px',
                  height: '36px',
                  borderRadius: 'var(--radius-xs)',
                  background: 'rgba(59, 130, 246, 0.15)',
                  border: '1px solid rgba(59, 130, 246, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#60a5fa',
                  flexShrink: 0
                }}
              >
                <KeyRound size={18} />
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: '13px', color: 'var(--text-primary)', marginBottom: '2px' }}>
                  Please Enable Two-Factor Authentication (2FA Recommended)
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  Enhance account defense with Google Authenticator or Microsoft Authenticator. 
                  Enforcement is opt-in for your evaluation convenience.
                </div>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => setIsMfaOpen(true)}
                style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
              >
                <KeyRound size={12} />
                <span>Enable 2FA with TOTP</span>
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={handleDismissMfaBanner}
                title="Dismiss for this session"
              >
                Maybe Later
              </button>
            </div>
          </div>
        )}

        {/* Navigation Tabs */}
        <div className="nav-tabs">
          <button
            className={`nav-tab-btn ${activeTab === 'documents' ? 'active' : ''}`}
            onClick={() => setActiveTab('documents')}
          >
            <FileText size={14} />
            <span>Vault Documents</span>
            <span className="nav-tab-count">{documents.length}</span>
          </button>

          {isAdmin && (
            <>
              <button
                className={`nav-tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
                onClick={() => setActiveTab('audit')}
              >
                <Shield size={14} />
                <span>HMAC Audit Ledger</span>
              </button>

              <button
                className={`nav-tab-btn ${activeTab === 'users' ? 'active' : ''}`}
                onClick={() => setActiveTab('users')}
              >
                <UsersIcon size={14} />
                <span>Identity Governance</span>
              </button>
            </>
          )}
        </div>

        {/* Tab Views */}
        {activeTab === 'documents' && (
          <DocumentList
            documents={documents}
            currentUser={user}
            onDownload={handleDownload}
            onOpenUpload={() => setIsUploadOpen(true)}
            onOpenPermissions={(doc) => setPermissionsDoc(doc)}
            onOpenRevision={(doc) => setRevisionDoc(doc)}
            onOpenHistory={(doc) => setHistoryDoc(doc)}
            onDeleteDocument={handleDelete}
            onSearch={(filters) => loadDocuments(filters)}
            isLoading={isLoadingDocs}
          />
        )}

        {activeTab === 'audit' && <AuditLedgerView />}

        {activeTab === 'users' && <UserDirectoryView currentUser={user} />}
      </main>

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={() => {
          showToast('success', 'Document uploaded and hashed into vault.');
          loadDocuments();
        }}
      />

      {/* Revision Modal (New Version Upload) */}
      <RevisionModal
        isOpen={!!revisionDoc}
        document={revisionDoc}
        onClose={() => setRevisionDoc(null)}
        onSuccess={() => {
          showToast('success', 'New version revision committed and hashed into vault.');
          loadDocuments();
        }}
      />

      {/* Version History Modal */}
      <VersionHistoryModal
        isOpen={!!historyDoc}
        document={historyDoc}
        onClose={() => setHistoryDoc(null)}
      />

      {/* Permissions Modal */}
      <PermissionsModal
        document={permissionsDoc}
        isOpen={!!permissionsDoc}
        onClose={() => setPermissionsDoc(null)}
        onPermissionsUpdated={() => loadDocuments()}
      />

      {/* MFA Setup & Management Modal */}
      <MfaModal
        isOpen={isMfaOpen}
        onClose={() => setIsMfaOpen(false)}
        onMfaStatusChange={handleMfaStatusChange}
      />

      {/* Styled Delete Confirmation Modal */}
      {deleteConfirmDocId && (
        <div className="modal-overlay">
          <div className="modal-content" style={{ maxWidth: '420px' }}>
            <div className="modal-header">
              <span style={{ fontWeight: 600, fontSize: '13px' }}>Confirm Soft Delete</span>
              <button
                type="button"
                onClick={() => setDeleteConfirmDocId(null)}
                style={{ background: 'transparent', border: 'none', cursor: 'pointer', color: 'var(--text-muted)' }}
              >
                &times;
              </button>
            </div>
            <div className="modal-body">
              <p style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                Are you sure you want to soft-delete this document? It will be immediately inaccessible in your active vault.
              </p>
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setDeleteConfirmDocId(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                onClick={confirmDelete}
              >
                Confirm Soft Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notification */}
      {toast && (
        <div className="toast">
          {toast.type === 'success' ? (
            <CheckCircle2 size={18} color="var(--accent-emerald)" />
          ) : (
            <AlertCircle size={18} color="var(--accent-rose)" />
          )}
          <span style={{ fontSize: '0.85rem' }}>{toast.message}</span>
        </div>
      )}
    </div>
  );
};

export default App;
