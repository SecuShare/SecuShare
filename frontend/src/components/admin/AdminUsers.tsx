import { useEffect, useState } from 'react';
import { Trash2, ShieldCheck, Mail } from 'lucide-react';
import { useAdminStore } from '../../store/adminStore';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function AdminUsers() {
  const { users, fetchUsers, deleteUser } = useAdminStore();
  const [confirmDelete, setConfirmDelete] = useState<string | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchUsers();
  }, [fetchUsers]);

  const handleDelete = async (userId: string) => {
    setError('');
    try {
      await deleteUser(userId);
      setConfirmDelete(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete user');
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
      <div className="p-4 border-b border-gray-200">
        <h3 className="text-lg font-semibold text-gray-900">Users ({users.length})</h3>
      </div>

      {error && (
        <div className="mx-4 mt-4 bg-red-50 text-red-700 text-sm px-4 py-2 rounded-lg border border-red-200">
          {error}
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="text-left text-xs font-medium text-gray-500 uppercase px-4 py-3">Email</th>
              <th className="text-left text-xs font-medium text-gray-500 uppercase px-4 py-3">Storage</th>
              <th className="text-left text-xs font-medium text-gray-500 uppercase px-4 py-3">Files</th>
              <th className="text-left text-xs font-medium text-gray-500 uppercase px-4 py-3">Status</th>
              <th className="text-left text-xs font-medium text-gray-500 uppercase px-4 py-3">Joined</th>
              <th className="text-right text-xs font-medium text-gray-500 uppercase px-4 py-3">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {users.map((user) => {
              const usagePercent = user.storage_quota_bytes > 0
                ? Math.round((user.storage_used_bytes / user.storage_quota_bytes) * 100)
                : 0;
              const safeUsagePercent = Math.max(0, Math.min(usagePercent, 100));
              const usageColorClass = usagePercent > 90
                ? 'accent-red-500'
                : usagePercent > 70
                  ? 'accent-yellow-500'
                  : 'accent-green-500';

              return (
                <tr key={user.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="text-sm font-medium text-gray-900">{user.email}</div>
                  </td>
                  <td className="px-4 py-3">
                    <div className="text-sm text-gray-600">
                      {formatBytes(user.storage_used_bytes)} / {formatBytes(user.storage_quota_bytes)}
                    </div>
                    <progress
                      className={`w-24 h-1.5 mt-1 ${usageColorClass}`}
                      value={safeUsagePercent}
                      max={100}
                    />
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">{user.file_count}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      {user.is_admin && (
                        <span className="inline-flex items-center gap-1 text-xs font-medium bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded-full">
                          <ShieldCheck className="w-3 h-3" />
                          Admin
                        </span>
                      )}
                      {user.is_email_verified && (
                        <span className="inline-flex items-center gap-1 text-xs font-medium bg-green-50 text-green-700 px-2 py-0.5 rounded-full">
                          <Mail className="w-3 h-3" />
                          Verified
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500">
                    {new Date(user.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {confirmDelete === user.id ? (
                      <div className="flex items-center gap-2 justify-end">
                        <button
                          onClick={() => handleDelete(user.id)}
                          className="text-xs bg-red-600 text-white px-3 py-1 rounded hover:bg-red-700 transition"
                        >
                          Confirm
                        </button>
                        <button
                          onClick={() => setConfirmDelete(null)}
                          className="text-xs bg-gray-200 text-gray-700 px-3 py-1 rounded hover:bg-gray-300 transition"
                        >
                          Cancel
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => setConfirmDelete(user.id)}
                        className="text-gray-400 hover:text-red-600 transition"
                        title="Delete user"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </td>
                </tr>
              );
            })}
            {users.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-gray-500">
                  No users found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
