import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuthStore } from '../../store';
import { authTrace, authTraceError, emailHint, newAuthTraceId } from '../../services/authTrace';
import { api } from '../../services/api';
import { formatFileSize } from '../../services/cryptoService';
import { useToast } from '../common/Toast';
import { Shield } from 'lucide-react';

export function LoginForm() {
  const defaultGuestMaxFileSize = 10 * 1024 * 1024;
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [guestMaxFileSize, setGuestMaxFileSize] = useState(defaultGuestMaxFileSize);
  const navigate = useNavigate();
  const login = useAuthStore((s) => s.login);
  const loginAsGuest = useAuthStore((s) => s.loginAsGuest);
  const showToast = useToast();

  useEffect(() => {
    let cancelled = false;

    const loadPublicSettings = async () => {
      try {
        const response = await api.getPublicSettings();
        const size = response.data?.max_file_size_guest;
        if (!cancelled && response.success && typeof size === 'number' && size > 0) {
          setGuestMaxFileSize(size);
        }
      } catch {
        // Keep fallback default if settings cannot be loaded.
      }
    };

    void loadPublicSettings();
    return () => {
      cancelled = true;
    };
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const traceId = newAuthTraceId('signin');
    authTrace(traceId, 'ui.login.submit', {
      email: emailHint(email),
      passwordLength: password.length,
      route: window.location.pathname,
    });
    setIsLoading(true);

    try {
      await login(email, password, traceId);
      authTrace(traceId, 'ui.login.success');
      showToast('Welcome back!', 'success');
      navigate('/');
    } catch (err) {
      authTraceError(traceId, 'ui.login.error', err);
      showToast(err instanceof Error ? err.message : 'Login failed', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  const handleGuestLogin = async () => {
    setIsLoading(true);
    try {
      await loginAsGuest();
      showToast('Guest session created', 'success');
      navigate('/');
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to create guest session', 'error');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gray-50 flex items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-2 mb-4">
            <Shield className="w-10 h-10 text-indigo-600" />
            <h1 className="text-3xl font-bold text-gray-900">SecuShare</h1>
          </div>
          <p className="text-gray-600">Secure, end-to-end encrypted file sharing</p>
        </div>

        <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-8">
          <h2 className="text-2xl font-semibold text-gray-900 mb-6">Sign In</h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none transition"
                placeholder="you@example.com"
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none transition"
                placeholder="Enter your password"
                required
                maxLength={128}
              />
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-indigo-600 text-white py-2 px-4 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isLoading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>

          <div className="mt-6">
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-gray-300"></div>
              </div>
              <div className="relative flex justify-center text-sm">
                <span className="px-2 bg-white text-gray-500">Or continue as</span>
              </div>
            </div>

            <button
              onClick={handleGuestLogin}
              disabled={isLoading}
              className="mt-4 w-full border border-gray-300 text-gray-700 py-2 px-4 rounded-lg hover:bg-gray-50 transition disabled:opacity-50"
            >
              Guest User ({formatFileSize(guestMaxFileSize)} limit)
            </button>
          </div>

          <p className="mt-6 text-center text-sm text-gray-600">
            Don't have an account?{' '}
            <Link to="/register" className="text-indigo-600 hover:text-indigo-700 font-medium">
              Sign up
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
