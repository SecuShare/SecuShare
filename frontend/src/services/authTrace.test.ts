import { describe, expect, it, vi } from 'vitest';
import { authTrace, authTraceError, emailHint, isAuthDebugEnabled, newAuthTraceId } from './authTrace';

describe('authTrace utilities', () => {
  it('formats email hints for valid and invalid email shapes', () => {
    expect(emailHint('alice@example.com')).toBe('a***@example.com');
    expect(emailHint('not-an-email')).toBe('n***');
  });

  it('creates trace IDs with the provided prefix', () => {
    const traceId = newAuthTraceId('signin');
    expect(traceId).toMatch(/^signin-/);
  });

  it('is enabled in dev/test mode', () => {
    expect(isAuthDebugEnabled()).toBe(true);
  });

  it('disables tracing when session flag is explicitly set to 0', () => {
    vi.mocked(sessionStorage.getItem).mockReturnValue('0');
    expect(isAuthDebugEnabled()).toBe(false);
  });

  it('enables tracing when session flag is explicitly set to 1', () => {
    vi.mocked(sessionStorage.getItem).mockReturnValue('1');
    expect(isAuthDebugEnabled()).toBe(true);
  });

  it('handles sessionStorage access errors gracefully', () => {
    vi.mocked(sessionStorage.getItem).mockImplementation(() => {
      throw new Error('storage denied');
    });
    expect(isAuthDebugEnabled()).toBe(true);
  });

  it('logs normal auth trace events', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    authTrace('trace-1', 'step.enter', { user: 'test' });
    expect(infoSpy).toHaveBeenCalledWith('[auth-trace][trace-1] step.enter', { user: 'test' });
  });

  it('logs auth trace with default empty details payload', () => {
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    authTrace('trace-1b', 'step.enter');
    expect(infoSpy).toHaveBeenCalledWith('[auth-trace][trace-1b] step.enter', {});
  });

  it('does not log authTrace when tracing is disabled', () => {
    vi.mocked(sessionStorage.getItem).mockReturnValue('0');
    const infoSpy = vi.spyOn(console, 'info').mockImplementation(() => {});
    authTrace('trace-no-log', 'step.hidden', { hidden: true });
    expect(infoSpy).not.toHaveBeenCalled();
  });

  it('logs error events with details and stack traces', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const error = new Error('boom');
    authTraceError('trace-2', 'step.fail', error, { source: 'test' });

    const [message, payload] = errorSpy.mock.calls[0] as [string, Record<string, unknown>];
    expect(message).toBe('[auth-trace][trace-2] step.fail');
    expect(payload).toMatchObject({
      source: 'test',
      error: 'boom',
    });
    expect(payload.stack).toBeTypeOf('string');
  });

  it('stringifies non-Error values in authTraceError', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    authTraceError('trace-3', 'step.fail', { code: 42 });

    const [, payload] = errorSpy.mock.calls[0] as [string, Record<string, unknown>];
    expect(payload.error).toBe('[object Object]');
  });

  it('does not log authTraceError when tracing is disabled', () => {
    vi.mocked(sessionStorage.getItem).mockReturnValue('0');
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    authTraceError('trace-disabled', 'step.fail', new Error('skip'));
    expect(errorSpy).not.toHaveBeenCalled();
  });
});
