import { useState } from 'react';
import { Trash2, CheckCircle } from 'lucide-react';
import { useAdminStore } from '../../store/adminStore';

export function AdminCleanup() {
  const { triggerCleanup } = useAdminStore();
  const [isRunning, setIsRunning] = useState(false);
  const [results, setResults] = useState<Record<string, string> | null>(null);
  const [error, setError] = useState('');
  const [showConfirm, setShowConfirm] = useState(false);

  const handleCleanup = async () => {
    setIsRunning(true);
    setError('');
    setResults(null);
    setShowConfirm(false);
    try {
      const res = await triggerCleanup();
      setResults(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Cleanup failed');
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-2">Manual Cleanup</h3>
      <p className="text-sm text-gray-600 mb-4">
        Remove expired files, shares, guest sessions, and pending registrations.
        This runs automatically every hour but can be triggered manually.
      </p>

      {error && (
        <div className="bg-red-50 text-red-700 text-sm px-4 py-2 rounded-lg border border-red-200 mb-4">
          {error}
        </div>
      )}

      {results && (
        <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-4">
          <div className="flex items-center gap-2 mb-2">
            <CheckCircle className="w-4 h-4 text-green-600" />
            <span className="text-sm font-medium text-green-800">Cleanup completed</span>
          </div>
          <ul className="text-sm text-green-700 space-y-1">
            {Object.entries(results).map(([key, value]) => (
              <li key={key} className="flex justify-between">
                <span className="capitalize">{key.replace(/_/g, ' ')}</span>
                <span className={value.startsWith('error') ? 'text-red-600' : ''}>{value}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {showConfirm ? (
        <div className="flex items-center gap-3">
          <button
            onClick={handleCleanup}
            disabled={isRunning}
            className="flex items-center gap-2 bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700 transition disabled:opacity-50"
          >
            <Trash2 className="w-4 h-4" />
            {isRunning ? 'Running...' : 'Confirm Cleanup'}
          </button>
          <button
            onClick={() => setShowConfirm(false)}
            className="text-gray-600 hover:text-gray-900 transition"
          >
            Cancel
          </button>
        </div>
      ) : (
        <button
          onClick={() => setShowConfirm(true)}
          className="flex items-center gap-2 bg-orange-500 text-white px-4 py-2 rounded-lg hover:bg-orange-600 transition"
        >
          <Trash2 className="w-4 h-4" />
          Run Cleanup
        </button>
      )}
    </div>
  );
}
