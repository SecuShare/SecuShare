import { useState } from 'react';
import { BarChart3, Settings, Users, Wrench } from 'lucide-react';
import { AdminStats } from './AdminStats';
import { AdminSettings } from './AdminSettings';
import { AdminUsers } from './AdminUsers';
import { AdminCleanup } from './AdminCleanup';

type Tab = 'overview' | 'settings' | 'users' | 'maintenance';

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: 'overview', label: 'Overview', icon: BarChart3 },
  { id: 'settings', label: 'Settings', icon: Settings },
  { id: 'users', label: 'Users', icon: Users },
  { id: 'maintenance', label: 'Maintenance', icon: Wrench },
];

export function AdminDashboard() {
  const [activeTab, setActiveTab] = useState<Tab>('overview');

  return (
    <div>
      <h1 className="text-2xl font-bold text-gray-900 mb-6">Admin Dashboard</h1>

      <div className="flex gap-1 mb-6 bg-gray-100 p-1 rounded-lg w-fit">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition ${
              activeTab === tab.id
                ? 'bg-white text-indigo-600 shadow-sm'
                : 'text-gray-600 hover:text-gray-900'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {activeTab === 'overview' && <AdminStats />}
      {activeTab === 'settings' && <AdminSettings />}
      {activeTab === 'users' && <AdminUsers />}
      {activeTab === 'maintenance' && <AdminCleanup />}
    </div>
  );
}
