// Client-side encryption service using Web Crypto API

const ALGORITHM = 'AES-GCM';
const KEY_LENGTH = 256;
const IV_LENGTH = 12;

export interface EncryptedFile {
  encryptedData: ArrayBuffer;
  iv: Uint8Array;
  key: CryptoKey;
  keyBase64: string;
  ivBase64: string;
  checksum: string;
}

export async function generateKey(): Promise<{ key: CryptoKey; keyBase64: string }> {
  const key = await crypto.subtle.generateKey(
    { name: ALGORITHM, length: KEY_LENGTH },
    true,
    ['encrypt', 'decrypt']
  );

  const exportedKey = await crypto.subtle.exportKey('raw', key);
  const keyBase64 = arrayBufferToBase64(exportedKey);

  return { key, keyBase64 };
}

export async function encryptFile(file: File): Promise<EncryptedFile> {
  const { key, keyBase64 } = await generateKey();
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ivBase64 = arrayBufferToBase64(iv.buffer as ArrayBuffer);

  const fileBuffer = await file.arrayBuffer();

  const encryptedData = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv: iv.buffer as ArrayBuffer },
    key,
    fileBuffer
  );

  const checksum = await calculateSHA256(encryptedData);

  return {
    encryptedData,
    iv,
    key,
    keyBase64,
    ivBase64,
    checksum,
  };
}

export async function decryptFile(
  encryptedData: ArrayBuffer,
  keyBase64: string,
  ivBase64: string
): Promise<ArrayBuffer> {
  const key = await importKey(keyBase64);
  const iv = base64ToArrayBuffer(ivBase64);

  const decryptedData = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv: iv.buffer as ArrayBuffer },
    key,
    encryptedData
  );

  return decryptedData;
}

export async function verifyChecksum(data: ArrayBuffer, expectedChecksum: string): Promise<boolean> {
  const actualChecksum = await calculateSHA256(data);
  return actualChecksum === expectedChecksum;
}

export async function calculateSHA256(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  return arrayBufferToHex(hashBuffer);
}

async function importKey(keyBase64: string): Promise<CryptoKey> {
  const keyData = base64ToArrayBuffer(keyBase64);
  return crypto.subtle.importKey(
    'raw',
    keyData.buffer as ArrayBuffer,
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ['decrypt']
  );
}

export async function deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: ALGORITHM, length: KEY_LENGTH },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptKeyWithPassword(
  keyBase64: string,
  password: string
): Promise<{ encryptedKey: string; salt: string; iv: string }> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));

  const derivedKey = await deriveKeyFromPassword(password, salt);

  const encoder = new TextEncoder();
  const keyData = encoder.encode(keyBase64);

  const encryptedKey = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv: iv.buffer as ArrayBuffer },
    derivedKey,
    keyData
  );

  return {
    encryptedKey: arrayBufferToBase64(encryptedKey),
    salt: arrayBufferToBase64(salt.buffer as ArrayBuffer),
    iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
  };
}

export async function decryptKeyWithPassword(
  encryptedKeyBase64: string,
  password: string,
  saltBase64: string,
  ivBase64: string
): Promise<string> {
  const salt = base64ToArrayBuffer(saltBase64);
  const iv = base64ToArrayBuffer(ivBase64);

  const derivedKey = await deriveKeyFromPassword(password, salt);

  const encryptedKey = base64ToArrayBuffer(encryptedKeyBase64);

  const decryptedKey = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv: iv.buffer as ArrayBuffer },
    derivedKey,
    encryptedKey.buffer as ArrayBuffer
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedKey);
}

function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}
