# SecuShare Frontend

React + TypeScript frontend for SecuShare.

## Requirements

- Node.js 20+
- npm 9+

## Environment

Create `frontend/.env`:

```env
VITE_API_URL=/api/v1
```

In Docker Compose, keep `VITE_API_URL=/api/v1` so frontend nginx proxies API calls to the backend service.

Use an absolute URL in local development if you are not proxying through the same origin:

```env
VITE_API_URL=http://localhost:8080/api/v1
```

## Commands

```bash
npm ci
npm run dev
```

Other commands:

```bash
npm run lint
npm run test
npm run test:coverage
npm run build
npm run preview
```

## Admin Dashboard

Admin users see an "Admin" link in the navigation bar. The admin dashboard (`/admin`) provides:

- **Overview**: Usage statistics (users, files, storage, shares, guest sessions)
- **Settings**: Runtime configuration for file size limits, quotas, email domain restrictions
- **Users**: User management table with delete capability
- **Maintenance**: Manual cleanup trigger for expired resources

On first launch (fresh database), all routes redirect to `/setup` where the initial admin account is created.

## Security Notes

- Authentication uses a secure `httpOnly` `auth_token` cookie (not browser storage).
- The frontend calls `/auth/logout` and clears local non-auth session data on logout.
- CSRF tokens are sent for state-changing requests.
- File encryption/decryption is done in the browser using Web Crypto (AES-GCM).
- Admin routes are guarded client-side (`AdminRoute` component) and server-side (`AdminMiddleware`).
