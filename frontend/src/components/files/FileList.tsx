import { useEffect, useState } from 'react';
import { useFileStore } from '../../store';
import { useToast } from '../common/Toast';
import { FileSharesPanel } from './FileSharesPanel';
import { formatFileSize } from '../../services/cryptoService';
import { FileIcon, Trash2, Share2, Clock } from 'lucide-react';
import type { File } from '../../types';

export function FileList() {
  const { files, isLoading, fetchFiles, removeFile, fetchStorageInfo, storageInfo } = useFileStore();
  const [shareFile, setShareFile] = useState<File | null>(null);
  const showToast = useToast();

  useEffect(() => {
    fetchFiles();
    fetchStorageInfo();
  }, [fetchFiles, fetchStorageInfo]);

  const handleDelete = async (file: File) => {
    if (!confirm(`Delete "${file.original_filename}"?`)) return;

    try {
      await removeFile(file.id);
      showToast('File deleted', 'success');
    } catch {
      showToast('Failed to delete file', 'error');
    }
  };

  if (isLoading) {
    return (
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8 text-center">
        <div className="animate-pulse">Loading files...</div>
      </div>
    );
  }

  if (files.length === 0) {
    return (
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
        <FileIcon className="w-12 h-12 text-gray-300 mx-auto mb-4" />
        <h3 className="text-lg font-medium text-gray-900 mb-2">No files yet</h3>
        <p className="text-gray-500">Upload a file to get started</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200">
      <div className="p-4 border-b border-gray-200">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-gray-900">My Files</h2>
          {storageInfo && (
            <span className="text-sm text-gray-500">
              {formatFileSize(storageInfo.used)} / {formatFileSize(storageInfo.quota)} used
            </span>
          )}
        </div>
      </div>

      <div className="divide-y divide-gray-100">
        {files.map((file) => (
          <div key={file.id} className="p-4 flex items-center gap-4 hover:bg-gray-50">
            <div className="w-10 h-10 bg-indigo-100 rounded-lg flex items-center justify-center flex-shrink-0">
              <FileIcon className="w-5 h-5 text-indigo-600" />
            </div>

            <div className="flex-1 min-w-0">
              <p className="font-medium text-gray-900 truncate">{file.original_filename}</p>
              <div className="flex items-center gap-3 text-sm text-gray-500">
                <span>{formatFileSize(file.file_size_bytes)}</span>
                <span>Uploaded {new Date(file.created_at).toLocaleDateString()}</span>
                {file.expires_at && (
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    Expires {new Date(file.expires_at).toLocaleDateString()}
                  </span>
                )}
              </div>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setShareFile(file)}
                className="p-2 text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition"
                title="Create or view share links"
              >
                <Share2 className="w-4 h-4" />
              </button>
              <button
                onClick={() => handleDelete(file)}
                className="p-2 text-gray-400 hover:text-red-600 hover:bg-red-50 rounded-lg transition"
                title="Delete"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {shareFile && (
        <FileSharesPanel
          file={shareFile}
          onClose={() => setShareFile(null)}
        />
      )}
    </div>
  );
}
