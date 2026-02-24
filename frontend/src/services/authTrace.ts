const AUTH_DEBUG_STORAGE_KEY = 'auth_debug';

function readSessionFlag(): string | null {
  try {
    return sessionStorage.getItem(AUTH_DEBUG_STORAGE_KEY);
  } catch {
    return null;
  }
}

export function isAuthDebugEnabled(): boolean {
  if (import.meta.env.DEV) {
    return true;
  }
  if (import.meta.env.VITE_AUTH_DEBUG === '1') {
    return true;
  }
  return readSessionFlag() === '1';
}

export function newAuthTraceId(prefix = 'auth'): string {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

export function emailHint(email: string): string {
  const trimmed = email.trim();
  const atIdx = trimmed.indexOf('@');
  if (atIdx <= 0) {
    return `${trimmed.slice(0, 1)}***`;
  }

  const local = trimmed.slice(0, atIdx);
  const domain = trimmed.slice(atIdx + 1);
  return `${local.slice(0, 1)}***@${domain}`;
}

export function authTrace(traceId: string, step: string, details?: Record<string, unknown>): void {
  if (!isAuthDebugEnabled()) {
    return;
  }
  console.info(`[auth-trace][${traceId}] ${step}`, details ?? {});
}

export function authTraceError(
  traceId: string,
  step: string,
  error: unknown,
  details?: Record<string, unknown>,
): void {
  if (!isAuthDebugEnabled()) {
    return;
  }

  const payload: Record<string, unknown> = {
    ...(details ?? {}),
    error: error instanceof Error ? error.message : String(error),
  };
  if (error instanceof Error && error.stack) {
    payload.stack = error.stack;
  }
  console.error(`[auth-trace][${traceId}] ${step}`, payload);
}
