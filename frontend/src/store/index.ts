import { create } from 'zustand';
import type { User, File, StorageInfo } from '../types';
import { api } from '../services/api';
import { authTrace, authTraceError, emailHint, newAuthTraceId } from '../services/authTrace';
import {
  opaqueLogin,
  requestRegistrationVerification,
  verifyRegistrationCode,
} from '../services/opaqueService';

const FILE_KEYS_STORAGE_KEY = 'fileKeys';
const SHARE_URLS_STORAGE_KEY = 'shareUrls';

function readJSONStorage<T>(storage: Storage, key: string, fallback: T): T {
  try {
    const raw = storage.getItem(key);
    if (!raw) return fallback;
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string, traceId?: string) => Promise<void>;
  register: (email: string, password: string) => Promise<string>;
  verifyRegistration: (email: string, verificationCode: string) => Promise<void>;
  loginAsGuest: () => Promise<void>;
  logout: () => void;
  checkAuth: () => Promise<void>;
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: false,
  isLoading: true,

  login: async (email: string, password: string, traceId?: string) => {
    const id = traceId ?? newAuthTraceId('store-login');
    authTrace(id, 'store.login.start', {
      email: emailHint(email),
      passwordLength: password.length,
    });

    try {
      const data = await opaqueLogin(email, password, id);
      api.setToken(data.token);
      set({ user: data.user, isAuthenticated: true });
      await useFileStore.getState().fetchStorageInfo();
      authTrace(id, 'store.login.success', {
        userId: data.user.id,
        isGuest: data.user.is_guest,
      });
    } catch (error) {
      authTraceError(id, 'store.login.failed', error);
      throw error;
    }
  },

  register: async (email: string, password: string) => {
    const data = await requestRegistrationVerification(email, password);
    return data.message || 'Verification code sent to your email';
  },

  verifyRegistration: async (email: string, verificationCode: string) => {
    const data = await verifyRegistrationCode(email, verificationCode);
    api.setToken(data.token);
    set({ user: data.user, isAuthenticated: true });
    await useFileStore.getState().fetchStorageInfo();
  },

  loginAsGuest: async () => {
    const response = await api.createGuestSession();
    if (!response.success || !response.data) {
      throw new Error(response.error || 'Failed to create guest session');
    }
    api.setToken(response.data.token);
    set({ user: response.data.user, isAuthenticated: true });
    await useFileStore.getState().fetchStorageInfo();
  },

  logout: () => {
    api.setToken(null);
    api.setCSRFToken(null);
    sessionStorage.removeItem(SHARE_URLS_STORAGE_KEY);
    sessionStorage.removeItem(FILE_KEYS_STORAGE_KEY);
    useFileStore.getState().reset();
    set({ user: null, isAuthenticated: false });
  },

  checkAuth: async () => {
    set({ isLoading: true });
    try {
      if (!api.getToken()) {
        set({ user: null, isAuthenticated: false, isLoading: false });
        return;
      }

      const response = await api.getCurrentUser();
      if (response.success && response.data) {
        set({ user: response.data, isAuthenticated: true });
        await useFileStore.getState().fetchStorageInfo();
      } else {
        api.setToken(null);
        set({ user: null, isAuthenticated: false });
      }
    } catch {
      api.setToken(null);
      set({ user: null, isAuthenticated: false });
    } finally {
      set({ isLoading: false });
    }
  },
}));

interface FileState {
  files: File[];
  storageInfo: StorageInfo | null;
  isLoading: boolean;
  // In-memory map of fileId -> encryption key (current session only)
  fileKeys: Record<string, string>;
  // shareId -> full share URL (persisted in sessionStorage for current browser session)
  shareUrls: Record<string, string>;
  fetchFiles: () => Promise<void>;
  fetchStorageInfo: () => Promise<void>;
  addFile: (file: File) => void;
  setFileKey: (fileId: string, key: string) => void;
  setShareUrl: (shareId: string, url: string) => void;
  removeFile: (fileId: string) => Promise<void>;
  reset: () => void;
}

export const useFileStore = create<FileState>((set, get) => ({
  files: [],
  storageInfo: null,
  isLoading: false,
  fileKeys: readJSONStorage<Record<string, string>>(sessionStorage, FILE_KEYS_STORAGE_KEY, {}),
  shareUrls: readJSONStorage<Record<string, string>>(sessionStorage, SHARE_URLS_STORAGE_KEY, {}),

  fetchFiles: async () => {
    set({ isLoading: true });
    try {
      const response = await api.getFiles();
      if (response.success && response.data) {
        const files = response.data;
        set((state) => {
          const existingIds = new Set(files.map((f) => f.id));
          const prunedFileKeys = Object.fromEntries(
            Object.entries(state.fileKeys).filter(([id]) => existingIds.has(id))
          );
          sessionStorage.setItem(FILE_KEYS_STORAGE_KEY, JSON.stringify(prunedFileKeys));
          return { files, fileKeys: prunedFileKeys };
        });
      }
    } finally {
      set({ isLoading: false });
    }
  },

  fetchStorageInfo: async () => {
    try {
      const response = await api.getStorageInfo();
      if (response.success && response.data) {
        set({ storageInfo: response.data });
      }
    } catch {
      // Ignore errors
    }
  },

  addFile: (file: File) => {
    set((state) => ({
      files: [file, ...state.files],
    }));
    get().fetchStorageInfo();
  },

  setFileKey: (fileId: string, key: string) => {
    set((state) => ({
      fileKeys: (() => {
        const updated = { ...state.fileKeys, [fileId]: key };
        sessionStorage.setItem(FILE_KEYS_STORAGE_KEY, JSON.stringify(updated));
        return updated;
      })(),
    }));
  },

  setShareUrl: (shareId: string, url: string) => {
    set((state) => {
      const updated = { ...state.shareUrls, [shareId]: url };
      sessionStorage.setItem(SHARE_URLS_STORAGE_KEY, JSON.stringify(updated));
      return { shareUrls: updated };
    });
  },

  removeFile: async (fileId: string) => {
    const response = await api.deleteFile(fileId);
    if (!response.success) {
      throw new Error(response.error || 'Failed to delete file');
    }

    set((state) => ({
      files: state.files.filter((f) => f.id !== fileId),
      fileKeys: (() => {
        const updated = Object.fromEntries(Object.entries(state.fileKeys).filter(([id]) => id !== fileId));
        sessionStorage.setItem(FILE_KEYS_STORAGE_KEY, JSON.stringify(updated));
        return updated;
      })(),
    }));
    get().fetchStorageInfo();
  },

  reset: () => {
    sessionStorage.removeItem(FILE_KEYS_STORAGE_KEY);
    sessionStorage.removeItem(SHARE_URLS_STORAGE_KEY);
    set({ files: [], storageInfo: null, fileKeys: {}, shareUrls: {} });
  },
}));
