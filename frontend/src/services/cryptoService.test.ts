import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  calculateSHA256,
  decryptFile,
  decryptKeyWithPassword,
  deriveKeyFromPassword,
  encryptFile,
  encryptKeyWithPassword,
  formatFileSize,
  generateKey,
  verifyChecksum,
} from './cryptoService';

describe('formatFileSize', () => {
  it('formats bytes, KB, MB and GB', () => {
    expect(formatFileSize(0)).toBe('0 Bytes');
    expect(formatFileSize(512)).toBe('512 Bytes');
    expect(formatFileSize(1024)).toBe('1 KB');
    expect(formatFileSize(1536)).toBe('1.5 KB');
    expect(formatFileSize(1048576)).toBe('1 MB');
    expect(formatFileSize(5368709120)).toBe('5 GB');
  });
});

describe('calculateSHA256', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('calls crypto.subtle.digest with SHA-256', async () => {
    const testData = new ArrayBuffer(10);
    await calculateSHA256(testData);
    expect(globalThis.crypto.subtle.digest).toHaveBeenCalledWith('SHA-256', testData);
  });
});

describe('generateKey', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('generates an AES-GCM 256-bit key and exports it', async () => {
    await generateKey();
    expect(globalThis.crypto.subtle.generateKey).toHaveBeenCalledWith(
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt'],
    );
    expect(globalThis.crypto.subtle.exportKey).toHaveBeenCalledWith('raw', expect.anything());
  });
});

describe('encryptFile', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns encrypted payload metadata', async () => {
    const mockFile = {
      arrayBuffer: vi.fn().mockResolvedValue(new ArrayBuffer(12)),
    } as unknown as File;
    const result = await encryptFile(mockFile);

    expect(result.encryptedData).toBeInstanceOf(ArrayBuffer);
    expect(result.iv).toBeInstanceOf(Uint8Array);
    expect(result.key).toBeTruthy();
    expect(result.keyBase64.length).toBeGreaterThan(0);
    expect(result.ivBase64.length).toBeGreaterThan(0);
    expect(result.checksum.length).toBe(64);
  });
});

describe('verifyChecksum', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns true when checksums match', async () => {
    const data = new ArrayBuffer(10);
    const checksum = await calculateSHA256(data);
    const result = await verifyChecksum(data, checksum);
    expect(result).toBe(true);
  });

  it('returns false when checksums do not match', async () => {
    const result = await verifyChecksum(new ArrayBuffer(10), 'deadbeef');
    expect(result).toBe(false);
  });
});

describe('decryptFile', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('imports key from base64 and decrypts using decoded iv', async () => {
    const keyBytes = new Uint8Array(32).fill(1);
    const ivBytes = new Uint8Array(12).fill(2);
    const encrypted = new Uint8Array([3, 4, 5]).buffer;

    const keyBase64 = btoa(String.fromCharCode(...keyBytes));
    const ivBase64 = btoa(String.fromCharCode(...ivBytes));

    const decrypted = await decryptFile(encrypted, keyBase64, ivBase64);

    expect(decrypted).toBeInstanceOf(ArrayBuffer);
    expect(globalThis.crypto.subtle.importKey).toHaveBeenCalledWith(
      'raw',
      expect.any(ArrayBuffer),
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    expect(globalThis.crypto.subtle.decrypt).toHaveBeenCalledWith(
      { name: 'AES-GCM', iv: expect.any(ArrayBuffer) },
      expect.anything(),
      encrypted,
    );
  });
});

describe('deriveKeyFromPassword', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('derives AES-GCM key material via PBKDF2 with hardened iterations', async () => {
    const salt = new Uint8Array(16).fill(7);
    const key = await deriveKeyFromPassword('password123', salt);

    expect(key).toBeTruthy();
    const [importFormat, importData, importAlgo, importExtractable, importUsages] =
      vi.mocked(globalThis.crypto.subtle.importKey).mock.calls[0];
    expect(importFormat).toBe('raw');
    expect(ArrayBuffer.isView(importData as ArrayBufferView)).toBe(true);
    expect(importAlgo).toBe('PBKDF2');
    expect(importExtractable).toBe(false);
    expect(importUsages).toEqual(['deriveKey']);
    expect(globalThis.crypto.subtle.deriveKey).toHaveBeenCalledWith(
      expect.objectContaining({
        name: 'PBKDF2',
        iterations: 1000000,
        hash: 'SHA-256',
      }),
      expect.anything(),
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  });
});

describe('encrypt/decrypt key with password', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('encrypts key material and returns wrapped key payload', async () => {
    const wrapped = await encryptKeyWithPassword('base64-file-key', 'Password!23');

    expect(wrapped.encryptedKey.length).toBeGreaterThan(0);
    expect(wrapped.salt.length).toBeGreaterThan(0);
    expect(wrapped.iv.length).toBeGreaterThan(0);
    const [params, keyArg, payload] = vi.mocked(globalThis.crypto.subtle.encrypt).mock.calls[0];
    expect(params).toEqual(expect.objectContaining({ name: 'AES-GCM', iv: expect.anything() }));
    expect(keyArg).toBeTruthy();
    expect(ArrayBuffer.isView(payload as ArrayBufferView)).toBe(true);
  });

  it('decrypts wrapped key payload back to UTF-8 string', async () => {
    const decodedKey = 'restored-file-key';
    const encoded = new TextEncoder().encode(decodedKey);
    vi.mocked(globalThis.crypto.subtle.decrypt).mockResolvedValueOnce(encoded.buffer as ArrayBuffer);

    const encryptedBytes = new Uint8Array([9, 8, 7, 6, 5]);
    const saltBytes = new Uint8Array(16).fill(4);
    const ivBytes = new Uint8Array(12).fill(3);

    const encryptedKeyBase64 = btoa(String.fromCharCode(...encryptedBytes));
    const saltBase64 = btoa(String.fromCharCode(...saltBytes));
    const ivBase64 = btoa(String.fromCharCode(...ivBytes));

    const decrypted = await decryptKeyWithPassword(
      encryptedKeyBase64,
      'Password!23',
      saltBase64,
      ivBase64,
    );

    expect(decrypted).toBe(decodedKey);
  });
});
