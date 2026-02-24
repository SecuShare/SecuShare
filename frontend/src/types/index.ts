export interface User {
  id: string;
  email?: string;
  storage_quota_bytes: number;
  storage_used_bytes: number;
  is_guest: boolean;
  is_admin?: boolean;
  expires_at?: string;
}

export interface File {
  id: string;
  owner_id?: string;
  guest_session_id?: string;
  original_filename: string;
  encrypted_filename: string;
  mime_type: string;
  file_size_bytes: number;
  encrypted_size_bytes: number;
  iv_base64: string;
  checksum_sha256: string;
  expires_at?: string;
  created_at: string;
}

export interface Share {
  id: string;
  file_id: string;
  max_downloads?: number;
  download_count: number;
  expires_at?: string;
  created_at: string;
  is_active: boolean;
}

export interface FileShare {
  id: string;
  file_id: string;
  has_password: boolean;
  max_downloads?: number;
  download_count: number;
  expires_at?: string;
  created_at: string;
  is_active: boolean;
}

export interface ShareInfo {
  id: string;
  file_name: string;
  file_size_bytes: number;
  mime_type: string;
  has_password: boolean;
  expires_at?: string;
  download_count: number;
  max_downloads?: number;
}

export interface StorageInfo {
  quota: number;
  used: number;
  free: number;
}

export interface AuthResponse {
  token: string;
  csrf_token?: string;
  user: User;
}

export interface VerificationResponse {
  message: string;
}

export interface APIResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface SetupStatus {
  setup_completed: boolean;
}

export interface AppSetting {
  key: string;
  value: string;
  updated_at: string;
}

export interface UsageStats {
  total_users: number;
  total_files: number;
  total_storage_used: number;
  total_shares: number;
  active_guest_sessions: number;
}

export interface AdminUserInfo {
  id: string;
  email: string;
  storage_quota_bytes: number;
  storage_used_bytes: number;
  file_count: number;
  is_admin: boolean;
  is_email_verified: boolean;
  created_at: string;
}

export interface PublicSettings {
  max_file_size_guest: number;
  max_file_size_user: number;
}
