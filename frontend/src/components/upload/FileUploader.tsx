import { useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useAuthStore, useFileStore } from '../../store';
import { useToast } from '../common/Toast';
import { encryptFile, encryptKeyWithPassword, formatFileSize } from '../../services/cryptoService';
import { api } from '../../services/api';
import { Upload, Lock, FileIcon, Clock, Download, Copy, CheckCircle2, AlertTriangle } from 'lucide-react';

interface ShareOptions {
  passwordEnabled: boolean;
  password: string;
  expiresIn: 'never' | '1h' | '24h' | '7d' | '30d' | 'custom';
  customExpiresAt: string; // datetime-local value used when expiresIn === 'custom'
  maxDownloads: string;
}

type UploaderStep =
  | { step: 'idle' }
  | { step: 'encrypting'; fileName: string }
  | { step: 'uploading'; fileName: string; progress: number }
  | { step: 'configuring'; fileId: string; encryptionKey: string; fileName: string }
  | { step: 'sharing'; fileId: string; encryptionKey: string; fileName: string; options: ShareOptions }
  | { step: 'done'; shareUrl: string; fileName: string; passwordEnabled: boolean }
  | { step: 'error'; message: string };

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
  { value: 'custom', label: 'Custom…' },
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

export function FileUploader() {
  const [step, setStep] = useState<UploaderStep>({ step: 'idle' });
  const [shareOptions, setShareOptions] = useState<ShareOptions>(DEFAULT_SHARE_OPTIONS);
  const [copied, setCopied] = useState(false);
  const [dragActive, setDragActive] = useState(false);
  const [isSkipping, setIsSkipping] = useState(false);
  const { user } = useAuthStore();
  const { addFile, setFileKey, setShareUrl, removeFile, storageInfo } = useFileStore();
  const showToast = useToast();

  const uploadFile = async (file: File) => {
    const maxSize = user?.is_guest ? 10 * 1024 * 1024 : 100 * 1024 * 1024;
    if (file.size > maxSize) {
      showToast(`File too large. Max: ${formatFileSize(maxSize)}`, 'error');
      return;
    }

    const availableSpace = storageInfo?.free ?? (user?.is_guest ? 10 * 1024 * 1024 : 1024 * 1024 * 1024);
    if (file.size > availableSpace) {
      showToast(`Not enough storage space. Available: ${formatFileSize(availableSpace)}`, 'error');
      return;
    }

    setStep({ step: 'encrypting', fileName: file.name });

    try {
      const encrypted = await encryptFile(file);
      setStep({ step: 'uploading', fileName: file.name, progress: 50 });

      const response = await api.uploadFile(encrypted.encryptedData, {
        original_filename: file.name,
        mime_type: file.type || 'application/octet-stream',
        file_size_bytes: file.size,
        encrypted_size_bytes: encrypted.encryptedData.byteLength,
        iv_base64: encrypted.ivBase64,
        checksum_sha256: encrypted.checksum,
      });

      if (!response.success || !response.data) {
        throw new Error(response.error || 'Upload failed');
      }

      const fileId = response.data.id;
      setFileKey(fileId, encrypted.keyBase64);
      addFile(response.data);

      setStep({ step: 'configuring', fileId, encryptionKey: encrypted.keyBase64, fileName: file.name });
      setShareOptions({ ...DEFAULT_SHARE_OPTIONS, expiresIn: user?.is_guest ? '1h' : '24h' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Upload failed';
      setStep({ step: 'error', message });
      showToast(message, 'error');
      setTimeout(() => setStep({ step: 'idle' }), 3000);
    }
  };

  const handleCreateLink = async () => {
    if (step.step !== 'configuring' || isSkipping) return;
    const { fileId, encryptionKey, fileName } = step;

    if (!encryptionKey) {
      showToast('Encryption key missing. Please re-upload the file.', 'error');
      return;
    }

    setStep({ step: 'sharing', fileId, encryptionKey, fileName, options: shareOptions });

    try {
      const shareData: Parameters<typeof api.createShare>[0] = { file_id: fileId };

      let encryptedKeyData: { key: string; salt: string; iv: string } | undefined;
      if (shareOptions.passwordEnabled && shareOptions.password) {
        const { encryptedKey, salt, iv } = await encryptKeyWithPassword(encryptionKey, shareOptions.password);
        encryptedKeyData = { key: encryptedKey, salt, iv };
        shareData.password = shareOptions.password;
      }

      const expires = expiresInToDate(shareOptions.expiresIn, shareOptions.customExpiresAt);
      if (expires) shareData.expires_at = expires;

      const maxDl = parseInt(shareOptions.maxDownloads, 10);
      if (!isNaN(maxDl) && maxDl > 0) shareData.max_downloads = maxDl;

      const shareResponse = await api.createShare(shareData);
      if (!shareResponse.success || !shareResponse.data) {
        throw new Error(shareResponse.error || 'Failed to create share link');
      }

      let shareUrl: string;
      const baseUrl = `${window.location.origin}/s/${shareResponse.data.id}`;
      if (encryptedKeyData) {
        const fragment = btoa(JSON.stringify(encryptedKeyData));
        shareUrl = `${baseUrl}#enc:${fragment}`;
      } else {
        shareUrl = `${baseUrl}#${encryptionKey}`;
      }

      setShareUrl(shareResponse.data.id, shareUrl);
      setStep({ step: 'done', shareUrl, fileName, passwordEnabled: shareOptions.passwordEnabled && !!shareOptions.password });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create share link';
      showToast(message, 'error');
      // Return to configuring with options preserved
      setStep({ step: 'configuring', fileId, encryptionKey, fileName });
    }
  };

  const handleSkip = async () => {
    if (step.step !== 'configuring' || isSkipping) return;
    const { fileId } = step;

    setIsSkipping(true);
    try {
      await removeFile(fileId);
      setShareOptions(DEFAULT_SHARE_OPTIONS);
      setStep({ step: 'idle' });
      showToast('Uploaded file removed. No share link was created.', 'info');
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to remove uploaded file';
      showToast(message, 'error');
    } finally {
      setIsSkipping(false);
    }
  };

  const handleCopy = async () => {
    if (step.step !== 'done') return;
    try {
      await navigator.clipboard.writeText(step.shareUrl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      showToast('Could not copy to clipboard', 'error');
    }
  };

  const onDrop = (acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      uploadFile(acceptedFiles[0]);
    }
  };

  const { getRootProps, getInputProps } = useDropzone({
    onDrop,
    onDragEnter: () => setDragActive(true),
    onDragLeave: () => setDragActive(false),
    multiple: false,
    disabled: step.step !== 'idle',
  });

  const isConfiguring = step.step === 'configuring';
  const isSharing = step.step === 'sharing';
  const isDone = step.step === 'done';
  const isUploading = step.step === 'encrypting' || step.step === 'uploading' || step.step === 'error';

  const createLinkDisabled =
    isSkipping ||
    isSharing ||
    (isConfiguring && shareOptions.passwordEnabled && !shareOptions.password) ||
    (isConfiguring && shareOptions.expiresIn === 'custom' && !shareOptions.customExpiresAt);

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
      <div className="flex items-center gap-2 mb-6">
        <Upload className="w-5 h-5 text-indigo-600" />
        <h2 className="text-xl font-semibold text-gray-900">Upload File</h2>
      </div>

      {/* Step 1: Dropzone (idle / encrypting / uploading / error) */}
      {!isConfiguring && !isSharing && !isDone && (
        <>
          <div
            {...getRootProps()}
            className={`border-2 border-dashed rounded-xl p-12 text-center transition ${
              step.step === 'idle'
                ? dragActive
                  ? 'border-indigo-500 bg-indigo-50 cursor-pointer'
                  : 'border-gray-300 hover:border-gray-400 cursor-pointer'
                : 'border-gray-200 bg-gray-50 cursor-not-allowed'
            }`}
          >
            <input {...getInputProps()} />
            <div className="flex flex-col items-center gap-4">
              <div className="w-16 h-16 bg-gray-100 rounded-full flex items-center justify-center">
                <FileIcon className="w-8 h-8 text-gray-400" />
              </div>
              <div>
                <p className="text-lg font-medium text-gray-900">
                  Drop your file here or click to browse
                </p>
                <p className="text-sm text-gray-500 mt-1">
                  Files are encrypted locally before upload
                </p>
              </div>
              <div className="flex items-center gap-1 text-xs text-green-600 bg-green-50 px-3 py-1 rounded-full">
                <Lock className="w-3 h-3" />
                End-to-end encrypted
              </div>
            </div>
          </div>

          {/* Progress bar for encrypting/uploading/error states */}
          {isUploading && (
            <div className="mt-6">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-gray-700">
                  {step.step === 'error' ? '' : (step as { fileName: string }).fileName}
                </span>
                <span className="text-sm text-gray-500">
                  {step.step === 'encrypting' && 'Encrypting...'}
                  {step.step === 'uploading' && 'Uploading...'}
                  {step.step === 'error' && 'Failed'}
                </span>
              </div>
              <progress
                value={
                  step.step === 'uploading'
                    ? step.progress
                    : step.step === 'encrypting'
                    ? 25
                    : 100
                }
                max={100}
                className={`w-full h-2 rounded-full overflow-hidden ${
                  step.step === 'error'
                    ? '[&::-moz-progress-bar]:bg-red-500 [&::-webkit-progress-value]:bg-red-500'
                    : '[&::-moz-progress-bar]:bg-indigo-600 [&::-webkit-progress-value]:bg-indigo-600'
                } [&::-webkit-progress-bar]:bg-gray-200 [&::-webkit-progress-bar]:rounded-full`}
              />
            </div>
          )}

          {/* Storage info — only on idle/upload steps */}
          {storageInfo && (
            <div className="mt-6 p-4 bg-gray-50 rounded-lg">
              <div className="flex items-center justify-between text-sm mb-2">
                <span className="text-gray-600">Storage Used</span>
                <span className="font-medium text-gray-900">
                  {formatFileSize(storageInfo.used)} / {formatFileSize(storageInfo.quota)}
                </span>
              </div>
              <progress
                value={Math.min(storageInfo.used, Math.max(storageInfo.quota, 1))}
                max={Math.max(storageInfo.quota, 1)}
                className="w-full h-2 rounded-full overflow-hidden [&::-moz-progress-bar]:bg-indigo-600 [&::-webkit-progress-value]:bg-indigo-600 [&::-webkit-progress-bar]:bg-gray-200 [&::-webkit-progress-bar]:rounded-full"
              />
            </div>
          )}
        </>
      )}

      {/* Step 2: Share Options (configuring / sharing) */}
      {(isConfiguring || isSharing) && (
        <div className="space-y-5">
          {/* File chip */}
          <div className="flex items-center gap-3 p-3 bg-indigo-50 border border-indigo-100 rounded-lg">
            <div className="w-9 h-9 bg-indigo-100 rounded-lg flex items-center justify-center flex-shrink-0">
              <FileIcon className="w-5 h-5 text-indigo-600" />
            </div>
            <div className="min-w-0">
              <p className="text-sm font-medium text-gray-900 truncate">
                {(step as { fileName: string }).fileName}
              </p>
              <p className="text-xs text-indigo-600">File uploaded. Set share options below.</p>
            </div>
          </div>

          {/* Password toggle */}
          <div>
            <label className="flex items-center gap-2 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={shareOptions.passwordEnabled}
                onChange={e =>
                  setShareOptions(o => ({ ...o, passwordEnabled: e.target.checked, password: '' }))
                }
                className="w-4 h-4 text-indigo-600 rounded border-gray-300 focus:ring-indigo-500"
                disabled={isSharing}
              />
              <Lock className="w-4 h-4 text-gray-500" />
              <span className="text-sm font-medium text-gray-700">Password protect</span>
            </label>
            {shareOptions.passwordEnabled && (
              <input
                type="password"
                value={shareOptions.password}
                onChange={e => setShareOptions(o => ({ ...o, password: e.target.value }))}
                placeholder="Enter password"
                disabled={isSharing}
                className="mt-2 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100"
              />
            )}
          </div>

          {/* Expiry */}
          <div>
            <label className="flex items-center gap-2 text-sm font-medium text-gray-700 mb-1">
              <Clock className="w-4 h-4 text-gray-500" />
              Expires
            </label>
            <select
              value={shareOptions.expiresIn}
              onChange={e => {
                const val = e.target.value as ShareOptions['expiresIn'];
                setShareOptions(o => ({
                  ...o,
                  expiresIn: val,
                  customExpiresAt: val !== 'custom' ? '' : o.customExpiresAt,
                }));
              }}
              disabled={isSharing}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100"
            >
              {(user?.is_guest ? GUEST_EXPIRATION_OPTIONS : AUTH_EXPIRATION_OPTIONS).map(opt => (
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
                onChange={e => setShareOptions(o => ({ ...o, customExpiresAt: e.target.value }))}
                disabled={isSharing}
                className="mt-2 w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100"
              />
            )}
          </div>

          {/* Max downloads */}
          <div>
            <label className="flex items-center gap-2 text-sm font-medium text-gray-700 mb-1">
              <Download className="w-4 h-4 text-gray-500" />
              Max downloads
            </label>
            <input
              type="number"
              value={shareOptions.maxDownloads}
              onChange={e => setShareOptions(o => ({ ...o, maxDownloads: e.target.value }))}
              placeholder="Unlimited"
              min="1"
              disabled={isSharing}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:bg-gray-100"
            />
          </div>

          {/* Action buttons */}
          <div className="flex gap-3">
            <button
              onClick={handleCreateLink}
              disabled={createLinkDisabled}
              className="flex-1 px-4 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              {isSharing ? 'Creating…' : 'Create Link'}
            </button>
            <button
              onClick={handleSkip}
              disabled={isSharing || isSkipping}
              className="px-4 py-2 bg-white text-gray-700 text-sm font-medium rounded-lg border border-gray-300 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed transition"
            >
              {isSkipping ? 'Skipping...' : 'Skip Link'}
            </button>
          </div>
        </div>
      )}

      {/* Step 3: Link Ready (done) */}
      {isDone && step.step === 'done' && (
        <div className="space-y-5">
          {/* Success header */}
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-6 h-6 text-green-500 flex-shrink-0" />
            <div>
              <p className="text-sm font-semibold text-gray-900">Link ready!</p>
              <p className="text-xs text-gray-500 truncate">{step.fileName}</p>
            </div>
          </div>

          {/* URL row */}
          <div className="flex gap-2">
            <input
              type="text"
              readOnly
              value={step.shareUrl}
              onClick={e => (e.target as HTMLInputElement).select()}
              className="flex-1 min-w-0 px-3 py-2 bg-gray-50 border border-gray-200 rounded-lg font-mono text-sm text-gray-700 truncate focus:outline-none focus:ring-2 focus:ring-indigo-500 cursor-text"
            />
            <button
              onClick={handleCopy}
              className="flex-shrink-0 flex items-center gap-1.5 px-3 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition"
            >
              {copied ? (
                <>
                  <CheckCircle2 className="w-4 h-4" />
                  Copied ✓
                </>
              ) : (
                <>
                  <Copy className="w-4 h-4" />
                  Copy
                </>
              )}
            </button>
          </div>

          {/* Security banner */}
          {step.passwordEnabled ? (
            <div className="flex items-start gap-2 p-3 bg-gray-50 border border-gray-200 rounded-lg text-xs text-gray-600">
              <Lock className="w-4 h-4 text-gray-400 flex-shrink-0 mt-0.5" />
              <span>Password protected. Share the password separately with recipients.</span>
            </div>
          ) : (
            <div className="flex items-start gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-700">
              <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>The decryption key is embedded in the link. Anyone with the link can download the file.</span>
            </div>
          )}

          {/* Reset button */}
          <button
            onClick={() => setStep({ step: 'idle' })}
            className="w-full px-4 py-2 bg-white text-gray-700 text-sm font-medium rounded-lg border border-gray-300 hover:bg-gray-50 transition"
          >
            Upload another file
          </button>
        </div>
      )}
    </div>
  );
}
