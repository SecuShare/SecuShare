import { useEffect } from 'react';
import { Users, FileText, HardDrive, Share2, Clock } from 'lucide-react';
import { useAdminStore } from '../../store/adminStore';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

export function AdminStats() {
  const { stats, fetchStats } = useAdminStore();

  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  if (!stats) {
    return <div className="text-gray-500">Loading stats...</div>;
  }

  const cards = [
    { label: 'Total Users', value: stats.total_users, icon: Users, color: 'text-blue-600 bg-blue-50' },
    { label: 'Total Files', value: stats.total_files, icon: FileText, color: 'text-green-600 bg-green-50' },
    { label: 'Storage Used', value: formatBytes(stats.total_storage_used), icon: HardDrive, color: 'text-purple-600 bg-purple-50' },
    { label: 'Active Shares', value: stats.total_shares, icon: Share2, color: 'text-orange-600 bg-orange-50' },
    { label: 'Guest Sessions', value: stats.active_guest_sessions, icon: Clock, color: 'text-gray-600 bg-gray-100' },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
      {cards.map((card) => (
        <div key={card.label} className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
          <div className="flex items-center gap-3 mb-2">
            <div className={`p-2 rounded-lg ${card.color}`}>
              <card.icon className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-gray-900">{card.value}</div>
          <div className="text-sm text-gray-500">{card.label}</div>
        </div>
      ))}
    </div>
  );
}
