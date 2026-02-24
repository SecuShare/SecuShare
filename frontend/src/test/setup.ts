import '@testing-library/jest-dom/vitest';
import { beforeEach, vi } from 'vitest';

// Mock crypto.subtle for tests
const mockCrypto = {
  subtle: {
    generateKey: vi.fn().mockResolvedValue({
      type: 'secret',
      algorithm: { name: 'AES-GCM', length: 256 },
    }),
    exportKey: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    importKey: vi.fn().mockResolvedValue({
      type: 'secret',
      algorithm: { name: 'AES-GCM' },
    }),
    encrypt: vi.fn().mockResolvedValue(new ArrayBuffer(64)),
    decrypt: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    digest: vi.fn().mockResolvedValue(new ArrayBuffer(32)),
    deriveKey: vi.fn().mockResolvedValue({
      type: 'secret',
      algorithm: { name: 'AES-GCM' },
    }),
  },
  getRandomValues: vi.fn((arr: Uint8Array) => {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
    return arr;
  }),
};

Object.defineProperty(globalThis, 'crypto', {
  value: mockCrypto,
});

// Mock browser storage
const storageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};

Object.defineProperty(globalThis, 'localStorage', {
  value: storageMock,
});

Object.defineProperty(globalThis, 'sessionStorage', {
  value: storageMock,
});

// Mock fetch
globalThis.fetch = vi.fn();

// Reset mocks between tests
beforeEach(() => {
  vi.clearAllMocks();
  storageMock.getItem.mockReturnValue(null);
});
