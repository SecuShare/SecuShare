import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './store';
import { api } from './services/api';
import { ToastProvider } from './components/common/Toast';
import { Layout } from './components/layout/Layout';
import { LoginForm } from './components/auth/LoginForm';
import { RegisterForm } from './components/auth/RegisterForm';
import { FileUploader } from './components/upload/FileUploader';
import { FileList } from './components/files/FileList';
import { FileDownloader } from './components/download/FileDownloader';
import { SetupWizard } from './components/admin/SetupWizard';
import { AdminDashboard } from './components/admin/AdminDashboard';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuthStore();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Layout>{children}</Layout>;
}

function AdminRoute({ children }: { children: React.ReactNode }) {
  const { user, isAuthenticated, isLoading } = useAuthStore();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Loading...</div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  if (!user?.is_admin) {
    return <Navigate to="/" replace />;
  }

  return <Layout>{children}</Layout>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuthStore();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Loading...</div>
      </div>
    );
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

function HomePage() {
  return (
    <div className="grid md:grid-cols-2 gap-8">
      <FileUploader />
      <div>
        <h2 className="text-xl font-semibold text-gray-900 mb-4">How it works</h2>
        <div className="space-y-4">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
            <h3 className="font-medium text-gray-900 mb-2">1. Upload</h3>
            <p className="text-sm text-gray-600">
              Your file is encrypted locally in your browser using AES-256-GCM before upload.
            </p>
          </div>
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
            <h3 className="font-medium text-gray-900 mb-2">2. Share</h3>
            <p className="text-sm text-gray-600">
              Generate a share link. The encryption key is embedded in the URL fragment, never sent to the server.
            </p>
          </div>
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4">
            <h3 className="font-medium text-gray-900 mb-2">3. Download</h3>
            <p className="text-sm text-gray-600">
              Recipients can download and decrypt the file directly in their browser.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

function App() {
  const checkAuth = useAuthStore((s) => s.checkAuth);
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);

  useEffect(() => {
    const init = async () => {
      try {
        const res = await api.getSetupStatus();
        if (res.success && res.data && !res.data.setup_completed) {
          setSetupRequired(true);
          return;
        }
      } catch {
        // If setup status check fails, proceed normally
      }
      setSetupRequired(false);
      await checkAuth();
    };
    init();
  }, [checkAuth]);

  if (setupRequired === null) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-gray-600">Loading...</div>
      </div>
    );
  }

  return (
    <ToastProvider>
      <BrowserRouter>
        <Routes>
          {/* Setup wizard (only when setup not completed) */}
          <Route
            path="/setup"
            element={setupRequired ? <SetupWizard /> : <Navigate to="/" replace />}
          />

          {/* If setup is required, redirect everything to /setup */}
          {setupRequired ? (
            <Route path="*" element={<Navigate to="/setup" replace />} />
          ) : (
            <>
              {/* Public download page (no auth required) */}
              <Route path="/s/:shareId" element={<FileDownloader />} />

              {/* Auth pages */}
              <Route
                path="/login"
                element={
                  <PublicRoute>
                    <LoginForm />
                  </PublicRoute>
                }
              />
              <Route
                path="/register"
                element={
                  <PublicRoute>
                    <RegisterForm />
                  </PublicRoute>
                }
              />

              {/* Admin dashboard */}
              <Route
                path="/admin"
                element={
                  <AdminRoute>
                    <AdminDashboard />
                  </AdminRoute>
                }
              />

              {/* Protected pages */}
              <Route
                path="/"
                element={
                  <ProtectedRoute>
                    <HomePage />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/files"
                element={
                  <ProtectedRoute>
                    <FileList />
                  </ProtectedRoute>
                }
              />

              {/* Fallback */}
              <Route path="*" element={<Navigate to="/" replace />} />
            </>
          )}
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  );
}

export default App;
