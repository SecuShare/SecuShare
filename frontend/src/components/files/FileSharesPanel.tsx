import { useState, useEffect } from 'react';
import { encryptKeyWithPassword } from '../../services/cryptoService';
import { useAuthStore, useFileStore } from '../../store';
import { useToast } from '../common/Toast';
import { api } from '../../services/api';
import { Copy, X, Lock, Clock, Download, Trash2, Share2, CheckCircle2, Info } from 'lucide-react';
import type { File as AppFile, FileShare } from '../../types';

interface FileSharesPanelProps {
  file: AppFile;
  onClose: () => void;
}

interface ShareOptions {
  passwordEnabled: boolean;
  password: string;
  expiresIn: 'never' | '1h' | '24h' | '7d' | '30d' | 'custom';
  customExpiresAt: string;
  maxDownloads: string;
}

const DEFAULT_SHARE_OPTIONS: ShareOptions = {
  passwordEnabled: false,
  password: '',
  expiresIn: '24h',
  customExpiresAt: '',
  maxDownloads: '',
};

const GUEST_EXPIRATION_OPTIONS = [
  { value: '1h', label: '1 Hour' },
  { value: '24h', label: '24 Hours' },
] as const;

const AUTH_EXPIRATION_OPTIONS = [
  { value: 'never', label: 'Never' },
  { value: '1h', label: '1 Hour' },
  { value: '24h', label: '24 Hours' },
  { value: '7d', label: '7 Days' },
  { value: '30d', label: '30 Days' },
  { value: 'custom', label: 'Custom...' },
] as const;

function expiresInToDate(expiresIn: ShareOptions['expiresIn'], customExpiresAt: string): string | undefined {
  if (expiresIn === 'never') return undefined;
  if (expiresIn === 'custom') return customExpiresAt ? new Date(customExpiresAt).toISOString() : undefined;
  const now = new Date();
  const map: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
  };
  return new Date(now.getTime() + map[expiresIn]).toISOString();
}

export function FileSharesPanel({ file, onClose }: FileSharesPanelProps) {
  const [shares, setShares] = useState<FileShare[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [shareOptions, setShareOptions] = useState<ShareOptions>(DEFAULT_SHARE_OPTIONS);
  const { user } = useAuthStore();
  const { fileKeys, shareUrls, setShareUrl } = useFileStore();
  const showToast = useToast();

  const refreshShares = async () => {
    setIsLoading(true);
    try {
      const res = await api.getFileShares(file.id);
      if (res.success && res.data) {
        setShares(res.data);
      }
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    api.getFileShares(file.id).then((res) => {
      if (!cancelled && res.success && res.data) {
        setShares(res.data);
      }
      if (!cancelled) setIsLoading(false);
    });
    return () => { cancelled = true; };
  }, [file.id]);

  const handleCopy = async (shareId: string) => {
    const url = shareUrls[shareId];
    if (!url) return;
    try {
      await navigator.clipboard.writeText(url);
      setCopiedId(shareId);
      setTimeout(() => setCopiedId(null), 2000);
      showToast('Link copied!', 'success');
    } catch {
      showToast('Could not copy to clipboard', 'error');
    }
  };

  const handleDeactivate = async (shareId: string) => {
    if (!confirm('Deactivate this share link? Anyone with the link will no longer be able to download the file.')) return;
    try {
      const res = await api.deactivateShare(shareId);
      if (!res.success) throw new Error(res.error);
      setShares((prev) => prev.map((s) => s.id === shareId ? { ...s, is_active: false } : s));
      showToast('Share link deactivated', 'success');
    } catch {
      showToast('Failed to deactivate share', 'error');
    }
  };

  const handleCreateLink = async () => {
    if (isCreating) return;

    const encryptionKey = fileKeys[file.id];
    if (!encryptionKey) {
      showToast('Cannot create link: encryption key is unavailable on this device. Upload the file again.', 'error');
      return;
    }

    setIsCreating(true);
    try {
      const shareData: Parameters<typeof api.createShare>[0] = { file_id: file.id };

      let encryptedKeyData: { key: string; salt: string; iv: string } | undefined;
      if (shareOptions.passwordEnabled && shareOptions.password) {
        const { encryptedKey, salt, iv } = await encryptKeyWithPassword(encryptionKey, shareOptions.password);
        encryptedKeyData = { key: encryptedKey, salt, iv };
        shareData.password = shareOptions.password;
      }

      const expires = expiresInToDate(shareOptions.expiresIn, shareOptions.customExpiresAt);
      if (expires) shareData.expires_at = expires;

      const maxDl = parseInt(shareOptions.maxDownloads, 10);
      if (!isNaN(maxDl) && maxDl > 0) {
        shareData.max_downloads = maxDl;
      }

      const createRes = await api.createShare(shareData);
      if (!createRes.success || !createRes.data) {
        throw new Error(createRes.error || 'Failed to create share link');
      }

      let shareUrl: string;
      const baseUrl = `${window.location.origin}/s/${createRes.data.id}`;
      if (encryptedKeyData) {
        const fragment = btoa(JSON.stringify(encryptedKeyData));
        shareUrl = `${baseUrl}#enc:${fragment}`;
      } else {
        shareUrl = `${baseUrl}#${encryptionKey}`;
      }
      setShareUrl(createRes.data.id, shareUrl);
      await refreshShares();

      showToast('Share link created', 'success');
      setShareOptions((prev) => ({ ...prev, password: '' }));
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to create share link', 'error');
    } finally {
      setIsCreating(false);
    }
  };

  const activeShares = shares.filter((s) => s.is_active);
  const inactiveShares = shares.filter((s) => !s.is_active);
  const hasUnavailableUrls = activeShares.some((s) => !shareUrls[s.id]);
  const hasLocalKey = !!fileKeys[file.id];
  const createLinkDisabled =
    isCreating ||
    !hasLocalKey ||
    (shareOptions.passwordEnabled && !shareOptions.password) ||
    (shareOptions.expiresIn === 'custom' && !shareOptions.customExpiresAt);

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-white rounded-xl shadow-xl max-w-lg w-full max-h-[80vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-gray-200 shrink-0">
          <div className="flex items-center gap-2 min-w-0">
            <Share2 className="w-5 h-5 text-indigo-600 shrink-0" />
            <div className="min-w-0">
              <h3 className="text-base font-semibold text-gray-900">Share Links</h3>
              <p className="text-xs text-gray-500 truncate">{file.original_filename}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 shrink-0 ml-4">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="overflow-y-auto flex-1 p-4 space-y-3">
          <div className="border border-gray-200 rounded-lg p-3 space-y-3">
            <p className="text-xs font-semibold text-gray-700">Create New Link</p>

            {!hasLocalKey && (
              <div className="flex items-start gap-2 p-2 bg-amber-50 border border-amber-100 rounded text-xs text-amber-700">
                <Info className="w-4 h-4 shrink-0 mt-0.5" />
                <span>Cannot create links for this file on this device because the encryption key is unavailable.</span>
              </div>
            )}

            <div>
              <label className="flex items-center gap-2 cursor-pointer select-none">
                <input
                  type="checkbox"
                  checked={shareOptions.passwordEnabled}
                  onChange={(e) =>
                    setShareOptions((o) => ({ ...o, passwordEnabled: e.target.checked, password: '' }))
                  }
                  className="w-4 h-4 text-indigo-600 rounded border-gray-300 focus:ring-indigo-500"
                  disabled={isCreating || !hasLocalKey}
                />
                <Lock className="w-4 h-4 text-gray-500" />
                <span className="text-sm font-medium text-gray-700">Password protect</span>
              </label>
              {shareOptions.passwordEnabled && (
                <input
                  type="password"
                  value={shareOptions.password}
                  onChange={(e) => setShareOptions((o) => ({ ...o, password: e.target.value }))}
                  placeholder="Enter password"
                  disabled={isCreating || !hasLocalKey}
                  className="mt-2 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100"
                />
              )}
            </div>

            <div>
              <label className="flex items-center gap-2 text-sm font-medium text-gray-700 mb-1">
                <Clock className="w-4 h-4 text-gray-500" />
                Expires
              </label>
              <select
                value={shareOptions.expiresIn}
                onChange={(e) => {
                  const val = e.target.value as ShareOptions['expiresIn'];
                  setShareOptions((o) => ({
                    ...o,
                    expiresIn: val,
                    customExpiresAt: val !== 'custom' ? '' : o.customExpiresAt,
                  }));
                }}
                disabled={isCreating || !hasLocalKey}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100"
              >
                {(user?.is_guest ? GUEST_EXPIRATION_OPTIONS : AUTH_EXPIRATION_OPTIONS).map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
              {shareOptions.expiresIn === 'custom' && (
                <input
                  type="datetime-local"
                  value={shareOptions.customExpiresAt}
                  min={new Date(Date.now() + 60_000).toISOString().slice(0, 16)}
                  onChange={(e) => setShareOptions((o) => ({ ...o, customExpiresAt: e.target.value }))}
                  disabled={isCreating || !hasLocalKey}
                  className="mt-2 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100"
                />
              )}
            </div>

            <div>
              <label className="flex items-center gap-2 text-sm font-medium text-gray-700 mb-1">
                <Download className="w-4 h-4 text-gray-500" />
                Max downloads
              </label>
              <input
                type="number"
                value={shareOptions.maxDownloads}
                onChange={(e) => setShareOptions((o) => ({ ...o, maxDownloads: e.target.value }))}
                placeholder="Unlimited"
                min="1"
                disabled={isCreating || !hasLocalKey}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100"
              />
            </div>

            <button
              onClick={handleCreateLink}
              disabled={createLinkDisabled}
              className="w-full inline-flex items-center justify-center px-4 py-2 bg-indigo-600 text-white text-xs font-semibold rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              {isCreating ? 'Creating...' : 'Create Link'}
            </button>
          </div>

          {isLoading ? (
            <div className="text-center text-gray-500 py-8 text-sm">Loading...</div>
          ) : shares.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-sm font-medium text-gray-500">No share links yet</p>
            </div>
          ) : (
            <>
              {hasUnavailableUrls && (
                <div className="flex items-start gap-2 p-3 bg-amber-50 border border-amber-100 rounded-lg text-xs text-amber-700">
                  <Info className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>Some link URLs are only available in the session they were created. You can create a new link from this panel.</span>
                </div>
              )}

              {/* Active shares */}
              {activeShares.length > 0 && (
                <div className="space-y-2">
                  {activeShares.map((share) => {
                    const url = shareUrls[share.id];
                    const isExpired = !!share.expires_at && new Date(share.expires_at) < new Date();
                    const limitReached = share.max_downloads != null && share.download_count >= share.max_downloads;
                    const isCopied = copiedId === share.id;

                    return (
                      <div key={share.id} className="border border-gray-200 rounded-lg p-3 space-y-2">
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-500">
                          {share.has_password && (
                            <span className="flex items-center gap-1">
                              <Lock className="w-3 h-3" /> Password protected
                            </span>
                          )}
                          {share.expires_at ? (
                            <span className={`flex items-center gap-1 ${isExpired ? 'text-red-500' : ''}`}>
                              <Clock className="w-3 h-3" />
                              {isExpired ? 'Expired' : `Expires ${new Date(share.expires_at).toLocaleDateString()}`}
                            </span>
                          ) : (
                            <span className="flex items-center gap-1">
                              <Clock className="w-3 h-3" /> No expiry
                            </span>
                          )}
                          <span className={`flex items-center gap-1 ${limitReached ? 'text-red-500' : ''}`}>
                            <Download className="w-3 h-3" />
                            {share.download_count}{share.max_downloads != null ? ` / ${share.max_downloads}` : ''} downloads
                          </span>
                        </div>

                        <div className="flex items-center gap-2">
                          {url ? (
                            <button
                              onClick={() => handleCopy(share.id)}
                              className="flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 bg-indigo-600 text-white text-xs font-medium rounded-lg hover:bg-indigo-700 transition"
                            >
                              {isCopied ? (
                                <><CheckCircle2 className="w-3.5 h-3.5" /> Copied!</>
                              ) : (
                                <><Copy className="w-3.5 h-3.5" /> Copy Link</>
                              )}
                            </button>
                          ) : (
                            <div className="flex-1 px-3 py-1.5 bg-gray-100 text-gray-400 text-xs rounded-lg text-center">
                              URL not available
                            </div>
                          )}
                          <button
                            onClick={() => handleDeactivate(share.id)}
                            className="p-1.5 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition"
                            title="Deactivate share link"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Inactive shares */}
              {inactiveShares.length > 0 && (
                <div>
                  <p className="text-xs text-gray-400 mb-2">
                    Deactivated ({inactiveShares.length})
                  </p>
                  <div className="space-y-2">
                    {inactiveShares.map((share) => (
                      <div key={share.id} className="border border-gray-100 rounded-lg p-3 opacity-50">
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-gray-400">
                          {share.has_password && (
                            <span className="flex items-center gap-1"><Lock className="w-3 h-3" /> Password</span>
                          )}
                          <span className="flex items-center gap-1">
                            <Download className="w-3 h-3" /> {share.download_count} downloads
                          </span>
                          <span className="text-red-400">Deactivated</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
