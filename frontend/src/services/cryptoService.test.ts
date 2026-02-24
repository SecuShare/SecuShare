import { beforeEach, describe, expect, it, vi } from 'vitest';
import {
  calculateSHA256,
  encryptFile,
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
});
