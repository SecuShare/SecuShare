import type { AuthResponse, VerificationResponse } from '../types';
import { authTrace, authTraceError, emailHint, newAuthTraceId } from './authTrace';
import { api } from './api';

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

export async function requestRegistrationVerification(
  email: string,
  password: string,
): Promise<VerificationResponse> {
  const traceId = newAuthTraceId('register-request');
  try {
    const normalizedEmail = normalizeEmail(email);
    authTrace(traceId, 'auth.register.request.start', {
      email: emailHint(normalizedEmail),
      passwordLength: password.length,
    });

    const result = await api.register(normalizedEmail, password);
    authTrace(traceId, 'auth.register.request.response', {
      success: result.success,
      hasData: !!result.data,
      error: result.error,
    });

    if (!result.success || !result.data) {
      throw new Error(result.error || 'Registration failed');
    }

    return result.data;
  } catch (error) {
    authTraceError(traceId, 'auth.register.request.failed', error);
    throw error;
  }
}

export async function verifyRegistrationCode(
  email: string,
  verificationCode: string,
): Promise<AuthResponse> {
  const traceId = newAuthTraceId('register-verify');
  try {
    const normalizedEmail = normalizeEmail(email);
    authTrace(traceId, 'auth.register.verify.start', {
      email: emailHint(normalizedEmail),
      verificationCodeLength: verificationCode.length,
    });

    const result = await api.verifyRegistration(normalizedEmail, verificationCode);
    authTrace(traceId, 'auth.register.verify.response', {
      success: result.success,
      hasData: !!result.data,
      error: result.error,
    });

    if (!result.success || !result.data) {
      throw new Error(result.error || 'Verification failed');
    }

    return result.data;
  } catch (error) {
    authTraceError(traceId, 'auth.register.verify.failed', error);
    throw error;
  }
}

export async function opaqueLogin(email: string, password: string, traceId?: string): Promise<AuthResponse> {
  const id = traceId ?? newAuthTraceId('login');
  try {
    const normalizedEmail = normalizeEmail(email);
    authTrace(id, 'auth.login.start', {
      email: emailHint(normalizedEmail),
      passwordLength: password.length,
    });

    const result = await api.login(normalizedEmail, password, id);
    authTrace(id, 'auth.login.response', {
      success: result.success,
      hasData: !!result.data,
      error: result.error,
    });

    if (!result.success || !result.data) {
      throw new Error(result.error || 'Invalid credentials');
    }

    authTrace(id, 'auth.login.success', {
      userId: result.data.user.id,
      isGuest: result.data.user.is_guest,
    });

    return result.data;
  } catch (error) {
    authTraceError(id, 'auth.login.failed', error);
    throw error;
  }
}
