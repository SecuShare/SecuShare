import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mockFetch = vi.fn();
const mockSessionStorage = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
};

vi.stubGlobal('fetch', mockFetch);
vi.stubGlobal('sessionStorage', mockSessionStorage);

function successResponse(data: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: async () => ({ success: true, data }),
  } as Response;
}

describe('APIService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockSessionStorage.getItem.mockReturnValue(null);
    document.cookie = '';
  });

  afterEach(() => {
    vi.resetModules();
  });

  it('stores and reads token from sessionStorage', async () => {
    const { api } = await import('./api');

    api.setToken('test-token');
    expect(mockSessionStorage.setItem).toHaveBeenCalledWith('token', 'test-token');

    api.setToken(null);
    expect(mockSessionStorage.removeItem).toHaveBeenCalledWith('token');

    mockSessionStorage.getItem.mockReturnValue('stored-token');
    expect(api.getToken()).toBe('stored-token');
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
    mockSessionStorage.getItem.mockReturnValue('stored-token');
    mockFetch.mockResolvedValueOnce(successResponse({
      id: 'u1',
      email: 'test@example.com',
      storage_quota_bytes: 1024,
      storage_used_bytes: 0,
      is_guest: false,
    }));

    const { api } = await import('./api');
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
});
