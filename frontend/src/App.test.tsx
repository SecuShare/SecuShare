// Copyright (c) 2026 Mounir IDRASSI
// Affiliation: AM Crypto (https://amcrypto.jp)
// License: MIT

import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import App from './App';
import { api } from './services/api';

const guestUser = {
  id: 'guest-1',
  storage_quota_bytes: 10 * 1024 * 1024,
  storage_used_bytes: 0,
  is_guest: true,
  expires_at: '2030-01-01T00:00:00Z',
};

describe('App logout flow', () => {
  beforeEach(() => {
    window.history.pushState({}, '', '/');

    vi.spyOn(api, 'getSetupStatus').mockResolvedValue({
      success: true,
      data: { setup_completed: true },
    });
    vi.spyOn(api, 'getCurrentUser').mockResolvedValue({
      success: true,
      data: guestUser,
    });
    vi.spyOn(api, 'getStorageInfo').mockResolvedValue({
      success: true,
      data: { quota: guestUser.storage_quota_bytes, used: 0, free: guestUser.storage_quota_bytes },
    });
    vi.spyOn(api, 'getPublicSettings').mockResolvedValue({
      success: true,
      data: {
        max_file_size_guest: 10 * 1024 * 1024,
        max_file_size_user: 100 * 1024 * 1024,
      },
    });
    vi.spyOn(api, 'logout').mockResolvedValue({
      success: true,
      data: { message: 'logged out' },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns to sign-in page after guest logout from protected home route', async () => {
    render(<App />);

    const signOutButton = await screen.findByRole('button', { name: /sign out/i });
    fireEvent.click(signOutButton);

    expect(await screen.findByRole('heading', { name: 'Sign In' })).toBeInTheDocument();
    expect(window.location.pathname).toBe('/login');
    expect(api.logout).toHaveBeenCalledTimes(1);
  });
});

