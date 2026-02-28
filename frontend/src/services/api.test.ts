import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockFetch = vi.fn();

vi.stubGlobal('fetch', mockFetch);

function successResponse(data: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => ({ success: true, data }),
  } as Response;
}

function errorResponse(status: number, error: string): Response {
  return {
    ok: false,
    status,
    json: async () => ({ error }),
  } as Response;
}

function nonJSONErrorResponse(status: number): Response {
  return {
    ok: false,
    status,
    json: async () => {
      throw new Error('invalid json');
    },
  } as Response;
}

describe('APIService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    document.cookie = 'csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
  });

  afterEach(() => {
    vi.resetModules();
  });

  it('stores and reads token in memory', async () => {
    const { api } = await import('./api');

    api.setToken('test-token');
    expect(api.getToken()).toBe('test-token');

    api.setToken(null);
    expect(api.getToken()).toBeNull();
  });

  it('calls register init endpoint', async () => {
    mockFetch.mockResolvedValueOnce(successResponse({ registration_response: 'reg-resp' }));
    const { api } = await import('./api');

    const result = await api.registerInit('test@example.com', 'reg-req');

    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/auth/register/init'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          email: 'test@example.com',
          registration_request: 'reg-req',
        }),
      }),
    );
  });

  it('calls registration request, verification and login endpoints', async () => {
    mockFetch
      .mockResolvedValueOnce(successResponse({ message: 'verification code sent to your email' }))
      .mockResolvedValueOnce(successResponse({
        token: 'jwt-verify',
        csrf_token: 'csrf-verify',
        user: {
          id: 'u1',
          email: 'test@example.com',
          storage_quota_bytes: 1024,
          storage_used_bytes: 0,
          is_guest: false,
        },
      }))
      .mockResolvedValueOnce(successResponse({
        token: 'jwt-login',
        csrf_token: 'csrf-login',
        user: {
          id: 'u1',
          email: 'test@example.com',
          storage_quota_bytes: 1024,
          storage_used_bytes: 0,
          is_guest: false,
        },
      }));

    const { api } = await import('./api');

    const registerResult = await api.register('test@example.com', 'password123');
    const verifyResult = await api.verifyRegistration('test@example.com', '123456');
    const loginResult = await api.login('test@example.com', 'password123');

    expect(registerResult.success).toBe(true);
    expect(verifyResult.success).toBe(true);
    expect(loginResult.success).toBe(true);
    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining('/auth/register'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'password123',
        }),
      }),
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('/auth/register/verify'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          email: 'test@example.com',
          verification_code: '123456',
        }),
      }),
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      3,
      expect.stringContaining('/auth/login'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          email: 'test@example.com',
          password: 'password123',
        }),
      }),
    );
  });

  it('calls register finish endpoint and stores csrf token from response', async () => {
    mockFetch.mockResolvedValueOnce(successResponse({
      token: 'jwt-finish',
      csrf_token: 'csrf-finish',
      user: {
        id: 'u2',
        email: 'finish@example.com',
        storage_quota_bytes: 1024,
        storage_used_bytes: 0,
        is_guest: false,
      },
    }));

    const { api } = await import('./api');
    const result = await api.registerFinish('finish@example.com', 'record-xyz');

    expect(result.success).toBe(true);
    expect(api.getCSRFToken()).toBe('csrf-finish');
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/auth/register/finish'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          email: 'finish@example.com',
          registration_record: 'record-xyz',
        }),
      }),
    );
  });

  it('calls login init and login finish endpoints', async () => {
    mockFetch
      .mockResolvedValueOnce(successResponse({ login_id: 'login-1', login_response: 'ke2' }))
      .mockResolvedValueOnce(successResponse({
        token: 'jwt',
        csrf_token: 'csrf-login',
        user: {
          id: 'u1',
          email: 'test@example.com',
          storage_quota_bytes: 1024,
          storage_used_bytes: 0,
          is_guest: false,
        },
      }));

    const { api } = await import('./api');

    const initResult = await api.loginInit('test@example.com', 'ke1');
    const finishResult = await api.loginFinish('login-1', 'ke3');

    expect(initResult.success).toBe(true);
    expect(finishResult.success).toBe(true);
    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining('/auth/login/init'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          email: 'test@example.com',
          start_login_request: 'ke1',
        }),
      }),
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('/auth/login/finish'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          login_id: 'login-1',
          finish_login_request: 'ke3',
        }),
      }),
    );
  });

  it('propagates login init and login finish exceptions', async () => {
    mockFetch.mockRejectedValueOnce(new Error('init boom'));
    const { api } = await import('./api');
    await expect(api.loginInit('test@example.com', 'ke1')).rejects.toThrow('init boom');

    mockFetch.mockRejectedValueOnce(new Error('finish boom'));
    await expect(api.loginFinish('login-1', 'ke3')).rejects.toThrow('finish boom');
  });

  it('propagates login exceptions', async () => {
    mockFetch.mockRejectedValueOnce(new Error('login boom'));
    const { api } = await import('./api');
    await expect(api.login('test@example.com', 'password123')).rejects.toThrow('login boom');
  });

  it('applies CSRF token from verification response to state-changing requests', async () => {
    mockFetch
      .mockResolvedValueOnce(successResponse({
        token: 'jwt',
        csrf_token: 'csrf-123',
        user: {
          id: 'u1',
          email: 'test@example.com',
          storage_quota_bytes: 1024,
          storage_used_bytes: 0,
          is_guest: false,
        },
      }))
      .mockResolvedValueOnce(successResponse({ id: 'share-123' }));

    const { api } = await import('./api');

    await api.verifyRegistration('test@example.com', '123456');
    await api.createShare({ file_id: 'file-1' });

    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('/shares/'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'X-CSRF-Token': 'csrf-123',
        }),
      }),
    );
  });

  it('sends auth header on authenticated GET requests', async () => {
    mockFetch.mockResolvedValueOnce(successResponse({
      id: 'u1',
      email: 'test@example.com',
      storage_quota_bytes: 1024,
      storage_used_bytes: 0,
      is_guest: false,
    }));

    const { api } = await import('./api');
    api.setToken('stored-token');
    const result = await api.getCurrentUser();

    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/auth/me'),
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer stored-token',
        }),
      }),
    );
  });

  it('returns API errors for non-ok responses', async () => {
    const { api } = await import('./api');
    mockFetch.mockResolvedValueOnce(errorResponse(401, 'unauthorized'));
    const result = await api.getCurrentUser();
    expect(result).toEqual({ success: false, error: 'unauthorized' });
  });

  it('falls back to status code when request error payload has no error field', async () => {
    const { api } = await import('./api');
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      json: async () => ({}),
    } as Response);

    const result = await api.getCurrentUser();
    expect(result).toEqual({ success: false, error: 'Request failed (403)' });
  });

  it('falls back to generic API error when error response is not JSON', async () => {
    const { api } = await import('./api');
    mockFetch.mockResolvedValueOnce(nonJSONErrorResponse(500));
    const result = await api.getCurrentUser();
    expect(result).toEqual({ success: false, error: 'Request failed' });
  });

  it('uses csrf token from cookie for state-changing requests', async () => {
    document.cookie = 'csrf_token=cookie-csrf';
    mockFetch.mockResolvedValueOnce(successResponse({ id: 'share-cookie' }));
    const { api } = await import('./api');

    const result = await api.createShare({ file_id: 'file-cookie' });

    expect(result.success).toBe(true);
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'X-CSRF-Token': 'cookie-csrf',
        }),
      }),
    );
  });

  it('maps timeout and network failures to user-friendly errors', async () => {
    const { api } = await import('./api');

    mockFetch.mockRejectedValueOnce(new DOMException('aborted', 'AbortError'));
    await expect(api.getFiles()).rejects.toThrow('Request timed out');

    mockFetch.mockRejectedValueOnce(new TypeError('fetch failed'));
    await expect(api.getFiles()).rejects.toThrow('Network error: unable to reach server');
  });

  it('aborts requests that exceed timeout duration', async () => {
    vi.useFakeTimers();
    try {
      mockFetch.mockImplementationOnce((_url, options) => new Promise((_, reject) => {
        const signal = options?.signal as AbortSignal | undefined;
        signal?.addEventListener('abort', () => {
          reject(new DOMException('aborted', 'AbortError'));
        });
      }));

      const { api } = await import('./api');
      const pending = api.getFiles();
      const assertion = expect(pending).rejects.toThrow('Request timed out');
      await vi.advanceTimersByTimeAsync(30001);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it('creates guest session and clears auth state on logout', async () => {
    mockFetch
      .mockResolvedValueOnce(successResponse({
        token: 'guest-jwt',
        csrf_token: 'csrf-guest',
        user: {
          id: 'guest-1',
          is_guest: true,
          storage_quota_bytes: 1024,
          storage_used_bytes: 0,
        },
      }))
      .mockResolvedValueOnce(successResponse({ message: 'logged out' }));

    const { api } = await import('./api');
    api.setToken('guest-jwt');
    const guestResult = await api.createGuestSession();
    expect(guestResult.success).toBe(true);
    expect(api.getCSRFToken()).toBe('csrf-guest');

    const logoutResult = await api.logout();
    expect(logoutResult.success).toBe(true);
    expect(api.getToken()).toBeNull();
    expect(api.getCSRFToken()).toBeNull();
    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('/auth/logout'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer guest-jwt',
          'X-CSRF-Token': 'csrf-guest',
        }),
      }),
    );
  });

  it('handles auth/setup success responses that do not include csrf token', async () => {
    const authDataWithoutCSRF = {
      token: 'jwt',
      user: {
        id: 'u-no-csrf',
        email: 'nocsrf@example.com',
        storage_quota_bytes: 1024,
        storage_used_bytes: 0,
        is_guest: false,
      },
    };

    mockFetch
      .mockResolvedValueOnce(successResponse(authDataWithoutCSRF)) // verifyRegistration
      .mockResolvedValueOnce(successResponse(authDataWithoutCSRF)) // login
      .mockResolvedValueOnce(successResponse(authDataWithoutCSRF)) // registerFinish
      .mockResolvedValueOnce(successResponse(authDataWithoutCSRF)) // loginFinish
      .mockResolvedValueOnce(successResponse(authDataWithoutCSRF)) // createGuestSession
      .mockResolvedValueOnce(successResponse(authDataWithoutCSRF)); // completeSetup

    const { api } = await import('./api');

    await api.verifyRegistration('nocsrf@example.com', '123456');
    await api.login('nocsrf@example.com', 'password123');
    await api.registerFinish('nocsrf@example.com', 'reg-record');
    await api.loginFinish('login-id', 'finish-record');
    await api.createGuestSession();
    await api.completeSetup('admin@example.com', 'password123');

    expect(api.getCSRFToken()).toBeNull();
  });

  it('uploads encrypted files with auth/csrf headers and handles upload errors', async () => {
    mockFetch.mockResolvedValueOnce(errorResponse(400, 'invalid metadata'));
    const { api } = await import('./api');
    api.setToken('upload-token');
    api.setCSRFToken('upload-csrf');

    const result = await api.uploadFile(new Uint8Array([1, 2, 3, 4]).buffer, {
      original_filename: 'secret.txt',
      mime_type: 'text/plain',
      file_size_bytes: 4,
      encrypted_size_bytes: 16,
      iv_base64: 'iv',
      checksum_sha256: 'checksum',
    });

    expect(result).toEqual({ success: false, error: 'invalid metadata' });
    const [, requestInit] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(requestInit.method).toBe('POST');
    expect(requestInit.headers).toEqual(expect.objectContaining({
      Authorization: 'Bearer upload-token',
      'X-CSRF-Token': 'upload-csrf',
    }));
    expect(requestInit.body).toBeInstanceOf(FormData);
  });

  it('falls back to status-based upload error when error payload is missing message', async () => {
    const { api } = await import('./api');
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 413,
      json: async () => ({}),
    } as Response);

    const result = await api.uploadFile(new Uint8Array([9, 9, 9]).buffer, {
      original_filename: 'big.bin',
      mime_type: 'application/octet-stream',
      file_size_bytes: 3,
      encrypted_size_bytes: 64,
      iv_base64: 'iv',
      checksum_sha256: 'checksum',
    });

    expect(result).toEqual({ success: false, error: 'Upload failed (413)' });
  });

  it('falls back to generic upload error when error body is not JSON', async () => {
    const { api } = await import('./api');
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: async () => {
        throw new Error('invalid json');
      },
    } as Response);

    const result = await api.uploadFile(new Uint8Array([8, 8, 8]).buffer, {
      original_filename: 'broken.bin',
      mime_type: 'application/octet-stream',
      file_size_bytes: 3,
      encrypted_size_bytes: 64,
      iv_base64: 'iv',
      checksum_sha256: 'checksum',
    });

    expect(result).toEqual({ success: false, error: 'Upload failed' });
  });

  it('uploads encrypted files and returns parsed API response on success', async () => {
    mockFetch.mockResolvedValueOnce(successResponse({ id: 'file-123' }));
    const { api } = await import('./api');

    const result = await api.uploadFile(new Uint8Array([5, 6, 7]).buffer, {
      original_filename: 'ok.bin',
      mime_type: 'application/octet-stream',
      file_size_bytes: 3,
      encrypted_size_bytes: 15,
      iv_base64: 'iv',
      checksum_sha256: 'checksum',
    });

    expect(result).toEqual({ success: true, data: { id: 'file-123' } });
  });

  it('passes default and explicit payloads for shared download and request-code endpoints', async () => {
    const downloadResponse = {
      ok: true,
      status: 200,
      json: async () => ({ success: true }),
      arrayBuffer: async () => new ArrayBuffer(0),
      headers: new Headers(),
    } as unknown as Response;

    mockFetch
      .mockResolvedValueOnce(successResponse({ message: 'sent' }))
      .mockResolvedValueOnce(downloadResponse)
      .mockResolvedValueOnce(downloadResponse);

    const { api } = await import('./api');
    api.setToken('download-token');

    const requestCodeResult = await api.requestDownloadCode('share-1', 'viewer@example.com');
    expect(requestCodeResult.success).toBe(true);
    expect(mockFetch).toHaveBeenNthCalledWith(
      1,
      expect.stringContaining('/shares/share-1/request-code'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ email: 'viewer@example.com' }),
      }),
    );

    await api.downloadSharedFile('share-1');
    await api.downloadSharedFile('share-1', {
      password: 'p@ss',
      email: 'viewer@example.com',
      verification_code: '123456',
    });
    api.setToken(null);
    await api.downloadSharedFile('share-1');

    expect(mockFetch).toHaveBeenNthCalledWith(
      2,
      expect.stringContaining('/shares/share-1/file'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          Authorization: 'Bearer download-token',
          'Content-Type': 'application/json',
        }),
        body: JSON.stringify({}),
      }),
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      3,
      expect.stringContaining('/shares/share-1/file'),
      expect.objectContaining({
        body: JSON.stringify({
          password: 'p@ss',
          email: 'viewer@example.com',
          verification_code: '123456',
        }),
      }),
    );
    expect(mockFetch).toHaveBeenNthCalledWith(
      4,
      expect.stringContaining('/shares/share-1/file'),
      expect.objectContaining({
        headers: expect.objectContaining({
          'Content-Type': 'application/json',
        }),
      }),
    );
    const [, fourthInit] = mockFetch.mock.calls[3] as [string, RequestInit];
    expect((fourthInit.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it('covers setup/admin/share helper endpoints', async () => {
    mockFetch
      .mockResolvedValueOnce(successResponse({ setup_completed: false })) // getSetupStatus
      .mockResolvedValueOnce(successResponse({
        token: 'setup-token',
        csrf_token: 'csrf-setup',
        user: {
          id: 'admin-1',
          email: 'admin@example.com',
          storage_quota_bytes: 1024,
          storage_used_bytes: 0,
          is_guest: false,
          is_admin: true,
        },
      })) // completeSetup
      .mockResolvedValueOnce(successResponse([{ key: 'max_file_size_guest', value: '10485760' }])) // getAdminSettings
      .mockResolvedValueOnce(successResponse({ message: 'ok' })) // updateAdminSettings
      .mockResolvedValueOnce(successResponse({ total_users: 1 })) // getAdminStats
      .mockResolvedValueOnce(successResponse([{ id: 'u1', email: 'user@example.com' }])) // getAdminUsers
      .mockResolvedValueOnce(successResponse({ message: 'deleted' })) // deleteAdminUser
      .mockResolvedValueOnce(successResponse({ shares: 'cleaned' })) // triggerAdminCleanup
      .mockResolvedValueOnce(successResponse({ max_file_size_guest: 10 })) // getPublicSettings
      .mockResolvedValueOnce(successResponse({ quota: 1000 })) // getStorageInfo
      .mockResolvedValueOnce(successResponse([{ id: 'f1' }])) // getFiles
      .mockResolvedValueOnce(successResponse({ message: 'deleted file' })) // deleteFile
      .mockResolvedValueOnce(successResponse({ id: 's1', file_name: 'shared.bin' })) // getShareInfo
      .mockResolvedValueOnce(successResponse([{ id: 's1' }])) // getFileShares
      .mockResolvedValueOnce(successResponse({ message: 'deactivated' })) // deactivateShare
      .mockResolvedValueOnce(successResponse({ id: 'share-new' })); // createShare

    const { api } = await import('./api');

    await api.getSetupStatus();
    await api.completeSetup('admin@example.com', 'password123');
    await api.getAdminSettings();
    await api.updateAdminSettings({ max_file_size_guest: '2048' });
    await api.getAdminStats();
    await api.getAdminUsers();
    await api.deleteAdminUser('u1');
    await api.triggerAdminCleanup();
    await api.getPublicSettings();
    await api.getStorageInfo();
    await api.getFiles();
    await api.deleteFile('f1');
    await api.getShareInfo('s1');
    await api.getFileShares('f1');
    await api.deactivateShare('s1');
    await api.createShare({ file_id: 'f1', allowed_emails: ['allowed@example.com'] });

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/admin/settings'),
      expect.objectContaining({
        method: 'PUT',
        headers: expect.objectContaining({
          'X-CSRF-Token': 'csrf-setup',
        }),
      }),
    );
    expect(mockFetch).toHaveBeenLastCalledWith(
      expect.stringContaining('/shares/'),
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          file_id: 'f1',
          allowed_emails: ['allowed@example.com'],
        }),
      }),
    );
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/auth/storage/quota'),
      expect.any(Object),
    );
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/files/f1'),
      expect.objectContaining({ method: 'DELETE' }),
    );
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('/shares/s1'),
      expect.any(Object),
    );
  });

  it('uses configured VITE_API_URL without fallback warning', async () => {
    vi.resetModules();
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});

    vi.stubEnv('VITE_API_URL', 'https://api.example.test/api/v1');
    try {
      mockFetch.mockResolvedValueOnce(successResponse({
        id: 'u1',
        email: 'configured@example.com',
        storage_quota_bytes: 1024,
        storage_used_bytes: 0,
        is_guest: false,
      }));

      const { api } = await import('./api');
      const result = await api.getCurrentUser();

      expect(result.success).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://api.example.test/api/v1/auth/me',
        expect.any(Object),
      );
      expect(warnSpy).not.toHaveBeenCalledWith(
        'VITE_API_URL is not configured. Falling back to /api/v1.',
      );
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
