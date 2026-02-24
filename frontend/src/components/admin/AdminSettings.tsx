import { useEffect, useState } from 'react';
import { Save } from 'lucide-react';
import { useAdminStore } from '../../store/adminStore';

function bytesToMB(bytes: string): string {
  const n = parseInt(bytes, 10);
  if (isNaN(n)) return '';
  return (n / (1024 * 1024)).toString();
}

function mbToBytes(mb: string): string {
  const n = parseFloat(mb);
  if (isNaN(n)) return '0';
  return Math.round(n * 1024 * 1024).toString();
}

const SETTING_LABELS: Record<string, { label: string; unit?: string; type: 'size_mb' | 'text' | 'number' }> = {
  max_file_size_guest: { label: 'Max File Size (Guest)', unit: 'MB', type: 'size_mb' },
  max_file_size_user: { label: 'Max File Size (User)', unit: 'MB', type: 'size_mb' },
  storage_quota_guest: { label: 'Storage Quota (Guest)', unit: 'MB', type: 'size_mb' },
  storage_quota_user: { label: 'Storage Quota (User)', unit: 'MB', type: 'size_mb' },
  allowed_email_domains: { label: 'Allowed Email Domains', type: 'text' },
  guest_session_duration_hours: { label: 'Guest Session Duration', unit: 'hours', type: 'number' },
};

export function AdminSettings() {
  const { settings, fetchSettings, updateSettings } = useAdminStore();
  const [formValues, setFormValues] = useState<Record<string, string>>({});
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState('');

  useEffect(() => {
    fetchSettings();
  }, [fetchSettings]);

  useEffect(() => {
    const values: Record<string, string> = {};
    for (const s of settings) {
      if (s.key === 'setup_completed') continue;
      const meta = SETTING_LABELS[s.key];
      if (meta?.type === 'size_mb') {
        values[s.key] = bytesToMB(s.value);
      } else {
        values[s.key] = s.value;
      }
    }
    setFormValues(values);
  }, [settings]);

  const handleSave = async () => {
    setIsSaving(true);
    setMessage('');
    try {
      const updates: Record<string, string> = {};
      for (const [key, val] of Object.entries(formValues)) {
        const meta = SETTING_LABELS[key];
        if (meta?.type === 'size_mb') {
          updates[key] = mbToBytes(val);
        } else {
          updates[key] = val;
        }
      }
      await updateSettings(updates);
      setMessage('Settings saved successfully');
    } catch (err) {
      setMessage(err instanceof Error ? err.message : 'Failed to save settings');
    } finally {
      setIsSaving(false);
    }
  };

  const editableKeys = Object.keys(formValues).filter((k) => k !== 'setup_completed');

  return (
    <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
      <h3 className="text-lg font-semibold text-gray-900 mb-4">Application Settings</h3>

      {message && (
        <div className={`text-sm px-4 py-2 rounded-lg mb-4 ${message.includes('success') ? 'bg-green-50 text-green-700 border border-green-200' : 'bg-red-50 text-red-700 border border-red-200'}`}>
          {message}
        </div>
      )}

      <div className="space-y-4">
        {editableKeys.map((key) => {
          const meta = SETTING_LABELS[key] || { label: key, type: 'text' };
          return (
            <div key={key}>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                {meta.label}
                {meta.unit && <span className="text-gray-400 ml-1">({meta.unit})</span>}
              </label>
              {key === 'allowed_email_domains' ? (
                <div>
                  <input
                    type="text"
                    value={formValues[key] || ''}
                    onChange={(e) => setFormValues({ ...formValues, [key]: e.target.value })}
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    placeholder="example.com, company.org (empty = all allowed)"
                  />
                  <p className="text-xs text-gray-500 mt-1">Comma-separated list. Leave empty to allow all domains.</p>
                </div>
              ) : (
                <input
                  type="number"
                  value={formValues[key] || ''}
                  onChange={(e) => setFormValues({ ...formValues, [key]: e.target.value })}
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  min="0"
                />
              )}
            </div>
          );
        })}
      </div>

      <button
        onClick={handleSave}
        disabled={isSaving}
        className="mt-6 flex items-center gap-2 bg-indigo-600 text-white px-4 py-2 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50"
      >
        <Save className="w-4 h-4" />
        {isSaving ? 'Saving...' : 'Save Settings'}
      </button>
    </div>
  );
}
