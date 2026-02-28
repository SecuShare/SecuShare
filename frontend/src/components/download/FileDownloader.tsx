import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { Shield, Lock, Download, FileIcon, AlertCircle, Loader2, Mail } from 'lucide-react';
import { api } from '../../services/api';
import { decryptFile, decryptKeyWithPassword, verifyChecksum, formatFileSize } from '../../services/cryptoService';
import { useToast } from '../common/Toast';
import { FrontendAttribution } from '../common/FrontendAttribution';
import type { ShareInfo } from '../../types';

export function FileDownloader() {
  const { shareId } = useParams<{ shareId: string }>();
  const [shareInfo, setShareInfo] = useState<ShareInfo | null>(null);
  const [password, setPassword] = useState('');
  const [email, setEmail] = useState('');
  const [verificationCode, setVerificationCode] = useState('');
  const [isLoading, setIsLoading] = useState(true);
  const [isDownloading, setIsDownloading] = useState(false);
  const [isRequestingCode, setIsRequestingCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const showToast = useToast();

  // Get encryption key from URL fragment (after #) and validate it's non-empty base64
  const rawFragment = window.location.hash.slice(1);
  const encryptionKey = rawFragment && /^[A-Za-z0-9+/=]+$/.test(rawFragment) ? rawFragment : '';
  const isEncryptedFragment = rawFragment.startsWith('enc:');
  const encryptedFragmentData = isEncryptedFragment ? rawFragment.slice(4) : '';

  useEffect(() => {
    const fetchShareInfo = async () => {
      if (!shareId) return;

      try {
        const response = await api.getShareInfo(shareId);
        if (response.success && response.data) {
          setShareInfo(response.data);
        } else {
          setError(response.error || 'Share not found');
        }
      } catch {
        setError('Failed to load share information');
      } finally {
        setIsLoading(false);
      }
    };

    fetchShareInfo();
  }, [shareId]);

  const handleDownload = async () => {
    if (!shareId || !shareInfo) return;

    if (shareInfo.has_password && !password) {
      showToast('Please enter the password', 'error');
      return;
    }

    if (!shareInfo.has_password && !encryptionKey) {
      setError('Encryption key missing from URL');
      return;
    }

    if (shareInfo.has_password && !isEncryptedFragment) {
      setError('Invalid share link: encrypted key missing from URL');
      return;
    }

    if (shareInfo.requires_email_verification) {
      if (!email.trim()) {
        showToast('Please enter your email address', 'error');
        return;
      }
      if (!verificationCode.trim()) {
        showToast('Please enter the verification code', 'error');
        return;
      }
    }

    setIsDownloading(true);
    setError(null);

    try {
      // Download encrypted file
      const response = await api.downloadSharedFile(shareId, {
        password: shareInfo.has_password ? password : undefined,
        email: shareInfo.requires_email_verification ? email.trim().toLowerCase() : undefined,
        verification_code: shareInfo.requires_email_verification ? verificationCode.trim() : undefined,
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Download failed');
      }

      // Get the real filename from download response headers (not the generic share info name)
      const originalFilename = response.headers.get('X-Original-Filename') || 'download';
      const mimeType = response.headers.get('X-Mime-Type') || 'application/octet-stream';
      const ivBase64 = response.headers.get('X-IV-Base64');
      const checksum = response.headers.get('X-Checksum-Sha256');

      if (!ivBase64 || !checksum) {
        throw new Error('Missing decryption metadata');
      }

      // Get encrypted data
      const encryptedData = await response.arrayBuffer();

      // Verify checksum
      const checksumValid = await verifyChecksum(encryptedData, checksum);
      if (!checksumValid) {
        throw new Error('File integrity check failed');
      }

      // For password-protected shares, decrypt the file key from URL fragment
      let keyToUse = encryptionKey;
      if (shareInfo.has_password && isEncryptedFragment) {
        let encryptedKeyData: { key?: string; salt?: string; iv?: string };
        try {
          const decoded = atob(encryptedFragmentData);
          encryptedKeyData = JSON.parse(decoded);
        } catch {
          throw new Error('Failed to parse encryption key data from URL');
        }
        if (!encryptedKeyData.key || !encryptedKeyData.salt || !encryptedKeyData.iv) {
          throw new Error('Invalid encryption key format in URL');
        }
        keyToUse = await decryptKeyWithPassword(
          encryptedKeyData.key,
          password,
          encryptedKeyData.salt,
          encryptedKeyData.iv
        );
      }

      // Decrypt file
      const decryptedData = await decryptFile(encryptedData, keyToUse, ivBase64);

      // Trigger download
      const blob = new Blob([decryptedData], { type: mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = originalFilename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      showToast('File downloaded successfully!', 'success');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Download failed');
      showToast('Download failed', 'error');
    } finally {
      setIsDownloading(false);
    }
  };

  const handleRequestCode = async () => {
    if (!shareId || !shareInfo?.requires_email_verification) return;
    if (!email.trim()) {
      showToast('Please enter your email address', 'error');
      return;
    }

    setIsRequestingCode(true);
    setError(null);
    try {
      const response = await api.requestDownloadCode(shareId, email.trim().toLowerCase());
      if (!response.success) {
        throw new Error(response.error || 'Failed to request verification code');
      }
      showToast(response.data?.message || 'If allowed, a verification code has been sent.', 'info');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to request verification code';
      setError(message);
      showToast(message, 'error');
    } finally {
      setIsRequestingCode(false);
    }
  };

  const renderPageShell = (content: React.ReactNode) => (
    <div className="min-h-screen bg-gray-50 flex flex-col">
      <div className="flex-1 flex items-center justify-center px-4 py-10">
        {content}
      </div>
      <FrontendAttribution />
    </div>
  );

  if (isLoading) {
    return renderPageShell(
      <div className="flex items-center gap-3 text-gray-600">
        <Loader2 className="w-6 h-6 animate-spin" />
        <span>Loading...</span>
      </div>
    );
  }

  if (error && !shareInfo) {
    return renderPageShell(
      <div className="text-center">
        <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
        <h2 className="text-xl font-semibold text-gray-900 mb-2">Share Not Found</h2>
        <p className="text-gray-600">{error}</p>
      </div>
    );
  }

  return renderPageShell(
    <div className="w-full max-w-md">
      <div className="text-center mb-8">
        <div className="flex items-center justify-center gap-2 mb-4">
          <Shield className="w-10 h-10 text-indigo-600" />
          <h1 className="text-3xl font-bold text-gray-900">SecuShare</h1>
        </div>
        <p className="text-gray-600">Secure file download</p>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
        <div className="flex items-center gap-4 mb-6">
          <div className="w-14 h-14 bg-indigo-100 rounded-xl flex items-center justify-center">
            <FileIcon className="w-7 h-7 text-indigo-600" />
          </div>
          <div>
            <h3 className="font-semibold text-gray-900">{shareInfo?.file_name}</h3>
            <p className="text-sm text-gray-500">{formatFileSize(shareInfo?.file_size_bytes || 0)}</p>
          </div>
        </div>

        <div className="flex items-center gap-2 text-xs text-green-600 bg-green-50 px-3 py-2 rounded-lg mb-6">
          <Lock className="w-3 h-3" />
          End-to-end encrypted
        </div>

        {shareInfo?.expires_at && !isNaN(new Date(shareInfo.expires_at).getTime()) && (
          <p className="text-sm text-gray-500 mb-4">
            Expires: {new Date(shareInfo.expires_at).toISOString().replace('T', ' ').slice(0, 19)} UTC
          </p>
        )}

        {shareInfo?.max_downloads && (
          <p className="text-sm text-gray-500 mb-4">
            Downloads: {shareInfo.download_count} / {shareInfo.max_downloads}
          </p>
        )}

        {shareInfo?.has_password && (
          <div className="mb-6">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Password required
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none"
              />
            </div>
          </div>
        )}

        {shareInfo?.requires_email_verification && (
          <div className="mb-6 space-y-3">
            <label className="block text-sm font-medium text-gray-700">
              Email verification required
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="Enter your email address"
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none"
              />
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value)}
                placeholder="Enter 6-digit code"
                className="flex-1 px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none"
              />
              <button
                type="button"
                onClick={handleRequestCode}
                disabled={isRequestingCode || !email.trim()}
                className="px-3 py-2 bg-white text-indigo-700 border border-indigo-200 rounded-lg hover:bg-indigo-50 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isRequestingCode ? 'Sending...' : 'Send code'}
              </button>
            </div>
            <p className="text-xs text-gray-500">
              Enter an allowlisted email to receive a one-time verification code.
            </p>
          </div>
        )}

        {error && (
          <div className="mb-4 p-3 bg-red-50 text-red-700 text-sm rounded-lg">
            {error}
          </div>
        )}

        <button
          onClick={handleDownload}
          disabled={
            isDownloading ||
            (shareInfo?.has_password && !password) ||
            (shareInfo?.requires_email_verification && (!email.trim() || !verificationCode.trim()))
          }
          className="w-full flex items-center justify-center gap-2 bg-indigo-600 text-white py-3 px-4 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isDownloading ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              Downloading...
            </>
          ) : (
            <>
              <Download className="w-5 h-5" />
              Download File
            </>
          )}
        </button>

        <p className="mt-4 text-xs text-center text-gray-500">
          File is decrypted locally in your browser. The server never sees your data.
        </p>
      </div>
    </div>
  );
}
