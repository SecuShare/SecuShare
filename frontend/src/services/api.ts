import type {
  User,
  File,
  Share,
  FileShare,
  ShareInfo,
  StorageInfo,
  AuthResponse,
  VerificationResponse,
  APIResponse,
  SetupStatus,
  AppSetting,
  UsageStats,
  AdminUserInfo,
  PublicSettings,
} from '../types';
import { authTrace, authTraceError, emailHint, newAuthTraceId } from './authTrace';

const API_BASE = import.meta.env.VITE_API_URL || '/api/v1';
if (!import.meta.env.VITE_API_URL) {
  console.warn('VITE_API_URL is not configured. Falling back to /api/v1.');
}

const REQUEST_TIMEOUT_MS = 30000;
const UPLOAD_TIMEOUT_MS = 300000; // 5 minutes for uploads

class APIService {
  private token: string | null = null;
  private csrfToken: string | null = null;

  setToken(token: string | null) {
    this.token = token;
  }

  getToken(): string | null {
    return this.token;
  }

  setCSRFToken(token: string | null) {
    this.csrfToken = token;
  }

  getCSRFToken(): string | null {
    if (!this.csrfToken) {
      // Fall back to reading from cookie
      const match = document.cookie.match(/(?:^|; )csrf_token=([^;]*)/);
      if (match) {
        this.csrfToken = match[1];
      }
    }
    return this.csrfToken;
  }

  private async fetchWithTimeout(url: string, options: RequestInit, timeoutMs: number): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        credentials: 'include',
        signal: controller.signal,
      });
      return response;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') {
        throw new Error('Request timed out');
      }
      if (error instanceof TypeError) {
        throw new Error('Network error: unable to reach server');
      }
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<APIResponse<T>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };

    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    // Include CSRF token for state-changing requests
    const method = (options.method || 'GET').toUpperCase();
    if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
      const csrf = this.getCSRFToken();
      if (csrf) {
        headers['X-CSRF-Token'] = csrf;
      }
    }

    const response = await this.fetchWithTimeout(
      `${API_BASE}${path}`,
      { ...options, headers },
      REQUEST_TIMEOUT_MS,
    );

    if (!response.ok) {
      const data = await response.json().catch(() => ({ error: 'Request failed' }));
      return { success: false, error: data.error || `Request failed (${response.status})` };
    }

    const data = await response.json();
    return data;
  }

  // Auth endpoints (one-shot email/password)
  async register(email: string, password: string): Promise<APIResponse<VerificationResponse>> {
    return this.request<VerificationResponse>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async verifyRegistration(email: string, verificationCode: string): Promise<APIResponse<AuthResponse>> {
    const result = await this.request<AuthResponse>('/auth/register/verify', {
      method: 'POST',
      body: JSON.stringify({ email, verification_code: verificationCode }),
    });
    if (result.success && result.data) {
      this.setToken(result.data.token || null);
      if (result.data.csrf_token) {
        this.setCSRFToken(result.data.csrf_token);
      }
    }
    return result;
  }

  async login(email: string, password: string, traceId?: string): Promise<APIResponse<AuthResponse>> {
    const id = traceId ?? newAuthTraceId('api-login');
    authTrace(id, 'api.login.request', {
      path: '/auth/login',
      email: emailHint(email),
      passwordLength: password.length,
      callerStack: new Error().stack?.split('\n').slice(2, 6).map((line) => line.trim()).join(' | '),
    });

    try {
      const result = await this.request<AuthResponse>('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ email, password }),
      });
      authTrace(id, 'api.login.response', {
        success: result.success,
        hasData: !!result.data,
        error: result.error,
      });
      if (result.success && result.data) {
        this.setToken(result.data.token || null);
        if (result.data.csrf_token) {
          this.setCSRFToken(result.data.csrf_token);
        }
      }
      return result;
    } catch (error) {
      authTraceError(id, 'api.login.exception', error);
      throw error;
    }
  }

  // Legacy OPAQUE 2-round endpoints kept for compatibility/debugging.
  async registerInit(
    email: string,
    registrationRequest: string,
  ): Promise<APIResponse<{ registration_response: string }>> {
    return this.request('/auth/register/init', {
      method: 'POST',
      body: JSON.stringify({ email, registration_request: registrationRequest }),
    });
  }

  async registerFinish(
    email: string,
    registrationRecord: string,
  ): Promise<APIResponse<AuthResponse>> {
    const result = await this.request<AuthResponse>('/auth/register/finish', {
      method: 'POST',
      body: JSON.stringify({ email, registration_record: registrationRecord }),
    });
    if (result.success && result.data) {
      this.setToken(result.data.token || null);
      if (result.data.csrf_token) {
        this.setCSRFToken(result.data.csrf_token);
      }
    }
    return result;
  }

  async loginInit(
    email: string,
    startLoginRequest: string,
    traceId?: string,
  ): Promise<APIResponse<{ login_id: string; login_response: string }>> {
    const id = traceId ?? newAuthTraceId('api-login-init');
    authTrace(id, 'api.loginInit.request', {
      path: '/auth/login/init',
      email: emailHint(email),
      startLoginRequestLength: startLoginRequest.length,
      callerStack: new Error().stack?.split('\n').slice(2, 6).map((line) => line.trim()).join(' | '),
    });

    try {
      const result = await this.request<{ login_id: string; login_response: string }>('/auth/login/init', {
        method: 'POST',
        body: JSON.stringify({ email, start_login_request: startLoginRequest }),
      });
      authTrace(id, 'api.loginInit.response', {
        success: result.success,
        hasData: !!result.data,
        error: result.error,
      });
      return result;
    } catch (error) {
      authTraceError(id, 'api.loginInit.exception', error);
      throw error;
    }
  }

  async loginFinish(
    loginId: string,
    finishLoginRequest: string,
    traceId?: string,
  ): Promise<APIResponse<AuthResponse>> {
    const id = traceId ?? newAuthTraceId('api-login-finish');
    authTrace(id, 'api.loginFinish.request', {
      path: '/auth/login/finish',
      loginId,
      finishLoginRequestLength: finishLoginRequest.length,
    });

    try {
      const result = await this.request<AuthResponse>('/auth/login/finish', {
        method: 'POST',
        body: JSON.stringify({ login_id: loginId, finish_login_request: finishLoginRequest }),
      });
      authTrace(id, 'api.loginFinish.response', {
        success: result.success,
        hasData: !!result.data,
        error: result.error,
      });
      if (result.success && result.data) {
        this.setToken(result.data.token || null);
        if (result.data.csrf_token) {
          this.setCSRFToken(result.data.csrf_token);
        }
      }
      return result;
    } catch (error) {
      authTraceError(id, 'api.loginFinish.exception', error);
      throw error;
    }
  }

  async createGuestSession(): Promise<APIResponse<AuthResponse>> {
    const result = await this.request<AuthResponse>('/auth/guest', {
      method: 'POST',
    });
    if (result.success && result.data) {
      this.setToken(result.data.token || null);
      if (result.data.csrf_token) {
        this.setCSRFToken(result.data.csrf_token);
      }
    }
    return result;
  }

  async logout(): Promise<APIResponse<{ message: string }>> {
    const result = await this.request<{ message: string }>('/auth/logout', {
      method: 'POST',
      body: JSON.stringify({}),
    });
    this.setToken(null);
    this.setCSRFToken(null);
    return result;
  }

  async getCurrentUser(): Promise<APIResponse<User>> {
    return this.request<User>('/auth/me');
  }

  async getStorageInfo(): Promise<APIResponse<StorageInfo>> {
    return this.request<StorageInfo>('/auth/storage/quota');
  }

  // File endpoints
  async uploadFile(
    encryptedFile: ArrayBuffer,
    metadata: {
      original_filename: string;
      mime_type: string;
      file_size_bytes: number;
      encrypted_size_bytes: number;
      iv_base64: string;
      checksum_sha256: string;
    }
  ): Promise<APIResponse<File>> {
    const formData = new FormData();
    const blob = new Blob([encryptedFile]);
    formData.append('file', blob, 'encrypted.bin');
    formData.append('original_filename', metadata.original_filename);
    formData.append('mime_type', metadata.mime_type);
    formData.append('file_size_bytes', metadata.file_size_bytes.toString());
    formData.append('encrypted_size_bytes', metadata.encrypted_size_bytes.toString());
    formData.append('iv_base64', metadata.iv_base64);
    formData.append('checksum_sha256', metadata.checksum_sha256);

    const headers: Record<string, string> = {};
    if (this.getToken()) {
      headers['Authorization'] = `Bearer ${this.getToken()}`;
    }
    const csrf = this.getCSRFToken();
    if (csrf) {
      headers['X-CSRF-Token'] = csrf;
    }

    const response = await this.fetchWithTimeout(
      `${API_BASE}/files/`,
      { method: 'POST', headers, body: formData },
      UPLOAD_TIMEOUT_MS,
    );

    if (!response.ok) {
      const data = await response.json().catch(() => ({ error: 'Upload failed' }));
      return { success: false, error: data.error || `Upload failed (${response.status})` };
    }

    return response.json();
  }

  async getFiles(): Promise<APIResponse<File[]>> {
    return this.request<File[]>('/files/');
  }

  async deleteFile(fileId: string): Promise<APIResponse<{ message: string }>> {
    return this.request(`/files/${fileId}`, {
      method: 'DELETE',
    });
  }

  // Share endpoints
  async createShare(data: {
    file_id: string;
    password?: string;
    allowed_emails?: string[];
    max_downloads?: number;
    expires_at?: string;
  }): Promise<APIResponse<Share>> {
    return this.request<Share>('/shares/', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getShareInfo(shareId: string): Promise<APIResponse<ShareInfo>> {
    return this.request<ShareInfo>(`/shares/${shareId}`);
  }

  async requestDownloadCode(shareId: string, email: string): Promise<APIResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/shares/${shareId}/request-code`, {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  }

  async downloadSharedFile(
    shareId: string,
    data: { password?: string; email?: string; verification_code?: string } = {},
  ): Promise<Response> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.getToken()) {
      headers['Authorization'] = `Bearer ${this.getToken()}`;
    }

    return this.fetchWithTimeout(
      `${API_BASE}/shares/${shareId}/file`,
      {
        method: 'POST',
        headers,
        body: JSON.stringify(data),
      },
      UPLOAD_TIMEOUT_MS,
    );
  }

  async getFileShares(fileId: string): Promise<APIResponse<FileShare[]>> {
    return this.request<FileShare[]>(`/files/${fileId}/shares`);
  }

  async deactivateShare(shareId: string): Promise<APIResponse<{ message: string }>> {
    return this.request(`/shares/${shareId}`, {
      method: 'DELETE',
    });
  }

  // Setup endpoints
  async getSetupStatus(): Promise<APIResponse<SetupStatus>> {
    return this.request<SetupStatus>('/setup/status');
  }

  async completeSetup(email: string, password: string): Promise<APIResponse<AuthResponse>> {
    const result = await this.request<AuthResponse>('/setup/complete', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    if (result.success && result.data) {
      this.setToken(result.data.token || null);
      if (result.data.csrf_token) {
        this.setCSRFToken(result.data.csrf_token);
      }
    }
    return result;
  }

  // Admin endpoints
  async getAdminSettings(): Promise<APIResponse<AppSetting[]>> {
    return this.request<AppSetting[]>('/admin/settings');
  }

  async updateAdminSettings(settings: Record<string, string>): Promise<APIResponse<{ message: string }>> {
    return this.request('/admin/settings', {
      method: 'PUT',
      body: JSON.stringify({ settings }),
    });
  }

  async getAdminStats(): Promise<APIResponse<UsageStats>> {
    return this.request<UsageStats>('/admin/stats');
  }

  async getAdminUsers(): Promise<APIResponse<AdminUserInfo[]>> {
    return this.request<AdminUserInfo[]>('/admin/users');
  }

  async deleteAdminUser(userId: string): Promise<APIResponse<{ message: string }>> {
    return this.request(`/admin/users/${userId}`, {
      method: 'DELETE',
    });
  }

  async triggerAdminCleanup(): Promise<APIResponse<Record<string, string>>> {
    return this.request('/admin/cleanup', {
      method: 'POST',
    });
  }

  async getPublicSettings(): Promise<APIResponse<PublicSettings>> {
    return this.request<PublicSettings>('/auth/settings');
  }
}

export const api = new APIService();
