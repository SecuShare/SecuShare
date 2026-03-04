// Copyright (c) 2026 Mounir IDRASSI
// Affiliation: AM Crypto (https://amcrypto.jp)
// License: MIT

import { beforeEach, describe, expect, it, vi } from 'vitest';

const registerMock = vi.fn();
const verifyRegistrationMock = vi.fn();
const loginMock = vi.fn();

const authTraceMock = vi.fn();
const authTraceErrorMock = vi.fn();
const emailHintMock = vi.fn((email: string) => `hint:${email}`);
const newAuthTraceIdMock = vi.fn((prefix: string) => `${prefix}-trace-id`);

vi.mock('./api', () => ({
  api: {
    register: registerMock,
    verifyRegistration: verifyRegistrationMock,
    login: loginMock,
  },
}));

vi.mock('./authTrace', () => ({
  authTrace: authTraceMock,
  authTraceError: authTraceErrorMock,
  emailHint: emailHintMock,
  newAuthTraceId: newAuthTraceIdMock,
}));

const sampleAuthData = {
  token: 'jwt-token',
  csrf_token: 'csrf-token',
  user: {
    id: 'user-1',
    email: 'user@example.com',
    storage_quota_bytes: 1024,
    storage_used_bytes: 0,
    is_guest: false,
  },
};

describe('opaqueService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    newAuthTraceIdMock.mockImplementation((prefix: string) => `${prefix}-trace-id`);
  });

  it('normalizes email and returns registration verification response', async () => {
    registerMock.mockResolvedValueOnce({
      success: true,
      data: { message: 'verification code sent' },
    });
    const { requestRegistrationVerification } = await import('./opaqueService');

    const result = await requestRegistrationVerification('  USER@Example.com  ', 'password123');

    expect(result).toEqual({ message: 'verification code sent' });
    expect(registerMock).toHaveBeenCalledWith('user@example.com', 'password123');
    expect(newAuthTraceIdMock).toHaveBeenCalledWith('register-request');
    expect(emailHintMock).toHaveBeenCalledWith('user@example.com');
    expect(authTraceMock).toHaveBeenCalledWith(
      'register-request-trace-id',
      'auth.register.request.response',
      expect.objectContaining({ success: true, hasData: true }),
    );
  });

  it('throws registration error from API payload when provided', async () => {
    registerMock.mockResolvedValueOnce({ success: false, error: 'Email already registered' });
    const { requestRegistrationVerification } = await import('./opaqueService');

    await expect(requestRegistrationVerification('user@example.com', 'password123'))
      .rejects.toThrow('Email already registered');

    expect(authTraceErrorMock).toHaveBeenCalledWith(
      'register-request-trace-id',
      'auth.register.request.failed',
      expect.any(Error),
    );
  });

  it('uses default registration failure message when API omits error and data', async () => {
    registerMock.mockResolvedValueOnce({ success: true });
    const { requestRegistrationVerification } = await import('./opaqueService');

    await expect(requestRegistrationVerification('user@example.com', 'password123'))
      .rejects.toThrow('Registration failed');
  });

  it('rethrows registration API exceptions', async () => {
    registerMock.mockRejectedValueOnce(new Error('register transport failure'));
    const { requestRegistrationVerification } = await import('./opaqueService');

    await expect(requestRegistrationVerification('user@example.com', 'password123'))
      .rejects.toThrow('register transport failure');
  });

  it('normalizes email and returns verified auth response', async () => {
    verifyRegistrationMock.mockResolvedValueOnce({
      success: true,
      data: sampleAuthData,
    });
    const { verifyRegistrationCode } = await import('./opaqueService');

    const result = await verifyRegistrationCode('  USER@Example.com  ', '123456');

    expect(result).toEqual(sampleAuthData);
    expect(verifyRegistrationMock).toHaveBeenCalledWith('user@example.com', '123456');
    expect(newAuthTraceIdMock).toHaveBeenCalledWith('register-verify');
  });

  it('throws verification error and fallback message for invalid verify responses', async () => {
    verifyRegistrationMock.mockResolvedValueOnce({ success: false, error: 'Invalid code' });
    const { verifyRegistrationCode } = await import('./opaqueService');

    await expect(verifyRegistrationCode('user@example.com', '123456')).rejects.toThrow('Invalid code');

    verifyRegistrationMock.mockResolvedValueOnce({ success: true });
    await expect(verifyRegistrationCode('user@example.com', '123456')).rejects.toThrow('Verification failed');
  });

  it('rethrows verification API exceptions', async () => {
    verifyRegistrationMock.mockRejectedValueOnce(new Error('verify transport failure'));
    const { verifyRegistrationCode } = await import('./opaqueService');

    await expect(verifyRegistrationCode('user@example.com', '123456'))
      .rejects.toThrow('verify transport failure');
  });

  it('uses explicit trace id for successful login', async () => {
    loginMock.mockResolvedValueOnce({ success: true, data: sampleAuthData });
    const { opaqueLogin } = await import('./opaqueService');

    const result = await opaqueLogin('  USER@Example.com  ', 'password123', 'explicit-trace');

    expect(result).toEqual(sampleAuthData);
    expect(loginMock).toHaveBeenCalledWith('user@example.com', 'password123', 'explicit-trace');
    expect(newAuthTraceIdMock).not.toHaveBeenCalledWith('login');
    expect(authTraceMock).toHaveBeenCalledWith(
      'explicit-trace',
      'auth.login.success',
      { userId: 'user-1', isGuest: false },
    );
  });

  it('generates trace id when login trace id is omitted', async () => {
    loginMock.mockResolvedValueOnce({ success: true, data: sampleAuthData });
    const { opaqueLogin } = await import('./opaqueService');

    await opaqueLogin('user@example.com', 'password123');

    expect(newAuthTraceIdMock).toHaveBeenCalledWith('login');
    expect(loginMock).toHaveBeenCalledWith('user@example.com', 'password123', 'login-trace-id');
  });

  it('throws login payload error and fallback invalid credentials message', async () => {
    loginMock.mockResolvedValueOnce({ success: false, error: 'Invalid password' });
    const { opaqueLogin } = await import('./opaqueService');

    await expect(opaqueLogin('user@example.com', 'password123')).rejects.toThrow('Invalid password');

    loginMock.mockResolvedValueOnce({ success: true });
    await expect(opaqueLogin('user@example.com', 'password123')).rejects.toThrow('Invalid credentials');
  });

  it('rethrows login API exceptions', async () => {
    loginMock.mockRejectedValueOnce(new Error('login transport failure'));
    const { opaqueLogin } = await import('./opaqueService');

    await expect(opaqueLogin('user@example.com', 'password123'))
      .rejects.toThrow('login transport failure');

    expect(authTraceErrorMock).toHaveBeenCalledWith(
      'login-trace-id',
      'auth.login.failed',
      expect.any(Error),
    );
  });
});
