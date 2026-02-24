import { create } from 'zustand';
import type { AppSetting, UsageStats, AdminUserInfo } from '../types';
import { api } from '../services/api';

interface AdminState {
  settings: AppSetting[];
  stats: UsageStats | null;
  users: AdminUserInfo[];
  isLoading: boolean;
  error: string | null;

  fetchSettings: () => Promise<void>;
  updateSettings: (settings: Record<string, string>) => Promise<void>;
  fetchStats: () => Promise<void>;
  fetchUsers: () => Promise<void>;
  deleteUser: (userId: string) => Promise<void>;
  triggerCleanup: () => Promise<Record<string, string>>;
}

export const useAdminStore = create<AdminState>((set) => ({
  settings: [],
  stats: null,
  users: [],
  isLoading: false,
  error: null,

  fetchSettings: async () => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.getAdminSettings();
      if (res.success && res.data) {
        set({ settings: res.data });
      } else {
        set({ error: res.error || 'Failed to load settings' });
      }
    } catch {
      set({ error: 'Failed to load settings' });
    } finally {
      set({ isLoading: false });
    }
  },

  updateSettings: async (settings: Record<string, string>) => {
    set({ error: null });
    const res = await api.updateAdminSettings(settings);
    if (!res.success) {
      throw new Error(res.error || 'Failed to update settings');
    }
    // Refresh settings after update
    const updated = await api.getAdminSettings();
    if (updated.success && updated.data) {
      set({ settings: updated.data });
    }
  },

  fetchStats: async () => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.getAdminStats();
      if (res.success && res.data) {
        set({ stats: res.data });
      }
    } catch {
      set({ error: 'Failed to load stats' });
    } finally {
      set({ isLoading: false });
    }
  },

  fetchUsers: async () => {
    set({ isLoading: true, error: null });
    try {
      const res = await api.getAdminUsers();
      if (res.success && res.data) {
        set({ users: res.data });
      }
    } catch {
      set({ error: 'Failed to load users' });
    } finally {
      set({ isLoading: false });
    }
  },

  deleteUser: async (userId: string) => {
    const res = await api.deleteAdminUser(userId);
    if (!res.success) {
      throw new Error(res.error || 'Failed to delete user');
    }
    set((state) => ({
      users: state.users.filter((u) => u.id !== userId),
    }));
  },

  triggerCleanup: async () => {
    const res = await api.triggerAdminCleanup();
    if (!res.success || !res.data) {
      throw new Error(res.error || 'Cleanup failed');
    }
    return res.data;
  },
}));
