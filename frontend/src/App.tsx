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
import { DocumentPreviewModal } from './components/DocumentPreviewModal';
import { fetchDocuments, downloadDocument, fetchDocumentBlobUrl, deleteDocument, apiLogin } from './api';

type Tab = 'documents' | 'audit' | 'users';

export const App: React.FC = () => {
  const [token, setToken] = useState<string | null>(localStorage.getItem('tv_token'));
  const [user, setUser] = useState<User | null>(
    localStorage.getItem('tv_user') ? JSON.parse(localStorage.getItem('tv_user')!) : null
  );

  const [activeTab, setActiveTab] = useState<Tab>('documents');
  const [documents, setDocuments] = useState<VaultDocument[]>([]);
  const [isLoadingDocs, setIsLoadingDocs] = useState(false);

  // Modals state
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [permissionsDoc, setPermissionsDoc] = useState<VaultDocument | null>(null);
  const [isMfaOpen, setIsMfaOpen] = useState(false);
  const [previewState, setPreviewState] = useState<{
    doc: VaultDocument;
    blobUrl: string;
    mimeType: string;
    canDownload: boolean;
  } | null>(null);

  // 2FA Prompt Banner state
  const [mfaBannerDismissed, setMfaBannerDismissed] = useState<boolean>(() => {
    return sessionStorage.getItem('tv_mfa_prompt_dismissed') === 'true';
  });

  // Toast notification state
  const [toast, setToast] = useState<{ type: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    if (token && user) {
      loadDocuments();
    }
  }, [token, user]);

  const showToast = (type: 'success' | 'error', message: string) => {
    setToast({ type, message });
    setTimeout(() => setToast(null), 4000);
  };

  const handleLoginSuccess = (newToken: string, newUser: User) => {
    setToken(newToken);
    setUser(newUser);
    localStorage.setItem('tv_token', newToken);
    localStorage.setItem('tv_user', JSON.stringify(newUser));
    showToast('success', `Signed in as ${newUser.name} (${newUser.role})`);
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('tv_token');
    localStorage.removeItem('tv_user');
    showToast('success', 'Logged out. Active session invalidated.');
  };

  const handleDismissMfaBanner = () => {
    sessionStorage.setItem('tv_mfa_prompt_dismissed', 'true');
    setMfaBannerDismissed(true);
  };

  const handleMfaStatusChange = () => {
    if (user) {
      const updatedUser = { ...user, mfaEnabled: true };
      setUser(updatedUser);
      localStorage.setItem('tv_user', JSON.stringify(updatedUser));
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
      if (data.token && data.user) {
        handleLoginSuccess(data.token, data.user);
        if (data.user.role !== 'ADMIN') {
          setActiveTab('documents');
        }
      }
    } catch (err: any) {
      showToast('error', `Failed to switch persona: ${err.message}`);
    }
  };

  const loadDocuments = async (filters?: any) => {
    if (!token) return;
    setIsLoadingDocs(true);
    try {
      const data = await fetchDocuments(token, filters);
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
    if (!token) return;
    showToast('success', `Streaming ${doc.originalFilename}...`);
    try {
      await downloadDocument(doc.id, doc.originalFilename, token);
      showToast('success', `Downloaded ${doc.originalFilename} safely.`);
      // Refresh documents list to immediately reflect Burn-on-Download grant self-destruct
      await loadDocuments();
    } catch (err: any) {
      showToast('error', `Download Refused: ${err.message}`);
    }
  };

  const handlePreview = async (doc: VaultDocument) => {
    if (!token) return;
    showToast('success', `Decrypting in-browser stream for ${doc.title}...`);
    try {
      const { blobUrl, mimeType } = await fetchDocumentBlobUrl(doc.id, token, true);
      const isOwner = doc.owner?.id === user?.id || doc.ownerId === user?.id;
      const myGrant = Array.isArray(doc.permissions) && doc.permissions.length > 0 ? doc.permissions[0] : null;
      const isPreviewOnly = !isOwner && !!myGrant?.previewOnly;
      const canDownload = (isOwner || !!myGrant) && !isPreviewOnly && user?.role !== 'ADMIN';

      setPreviewState({
        doc,
        blobUrl,
        mimeType,
        canDownload
      });
      showToast('success', `In-browser preview ready for ${doc.originalFilename}.`);
    } catch (err: any) {
      showToast('error', `Preview Refused: ${err.message}`);
    }
  };

  const handleDelete = async (docId: string) => {
    if (!token) return;
    if (!window.confirm('Are you sure you want to soft-delete this document?')) return;
    try {
      await deleteDocument(docId, token);
      showToast('success', 'Document soft-deleted.');
      await loadDocuments();
    } catch (err: any) {
      showToast('error', err.message);
    }
  };

  if (!token || !user) {
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
            onPreview={handlePreview}
            onOpenUpload={() => setIsUploadOpen(true)}
            onOpenPermissions={(doc) => setPermissionsDoc(doc)}
            onDeleteDocument={handleDelete}
            onSearch={(filters) => loadDocuments(filters)}
            isLoading={isLoadingDocs}
          />
        )}

        {activeTab === 'audit' && <AuditLedgerView token={token} />}

        {activeTab === 'users' && <UserDirectoryView token={token} currentUser={user} />}
      </main>

      {/* Upload Modal */}
      <UploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onUploadSuccess={() => {
          showToast('success', 'Document uploaded and hashed into vault.');
          loadDocuments();
        }}
        token={token}
      />

      {/* Document In-App Preview Modal */}
      {previewState && (
        <DocumentPreviewModal
          document={previewState.doc}
          blobUrl={previewState.blobUrl}
          mimeType={previewState.mimeType}
          canDownload={previewState.canDownload}
          onClose={() => setPreviewState(null)}
          onDownload={() => {
            handleDownload(previewState.doc);
            setPreviewState(null);
          }}
        />
      )}

      {/* Permissions Modal */}
      <PermissionsModal
        document={permissionsDoc}
        isOpen={!!permissionsDoc}
        onClose={() => setPermissionsDoc(null)}
        token={token}
      />

      {/* MFA Setup & Management Modal */}
      {token && (
        <MfaModal
          isOpen={isMfaOpen}
          onClose={() => setIsMfaOpen(false)}
          token={token}
          onMfaStatusChange={handleMfaStatusChange}
        />
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
