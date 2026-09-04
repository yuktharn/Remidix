import { useState, useEffect } from 'react';
import { GitBranch, LogOut, CheckCircle2, AlertCircle, Loader2 } from 'lucide-react';

const API_URL = 'http://localhost:4000';

export default function GitHubLogin({ onAuthChange }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const ghConnected = params.get('github_connected');
    const ghError = params.get('github_error');

    // Clean URL params immediately
    if (ghConnected || ghError) {
      window.history.replaceState({}, '', window.location.pathname);
    }

    if (ghConnected) {
      setSuccessMsg(`GitHub connected successfully as @${ghConnected}. You can now create Pull Requests.`);
    }
    if (ghError) {
      setError(ghError);
    }

    checkSession(ghConnected);
  }, []);

  const checkSession = async (connectedUsername) => {
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/auth/github/session`, {
        credentials: 'include',
      });
      if (res.ok) {
        const data = await res.json();
        if (data.authenticated && data.user) {
          setUser(data.user);
          localStorage.setItem('user_id', String(data.user.id));
          localStorage.setItem('github_username', data.user.username);
          if (onAuthChange) onAuthChange(data.user);
          return;
        }
      }
      // Not authenticated — clear any leftover success message
      if (connectedUsername) setSuccessMsg(null);
    } catch {
      // Session check failed - not logged in
      if (connectedUsername) setSuccessMsg(null);
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = () => {
    setError(null);
    setSuccessMsg(null);
    window.location.href = `${API_URL}/auth/github/login`;
  };

  const handleLogout = async () => {
    setLoading(true);
    try {
      await fetch(`${API_URL}/auth/github/logout`, {
        method: 'POST',
        credentials: 'include',
      });
    } catch { /* ignore */ }
    localStorage.removeItem('user_id');
    localStorage.removeItem('github_username');
    setUser(null);
    setError(null);
    setSuccessMsg(null);
    setLoading(false);
    if (onAuthChange) onAuthChange(null);
  };

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '20px' }}>
        <Loader2 size={24} style={{ animation: 'spin 1s linear infinite' }} />
      </div>
    );
  }

  if (user) {
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px', padding: '10px 14px', background: 'rgba(79,208,138,0.08)', border: '1px solid rgba(79,208,138,0.25)', borderRadius: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: 0 }}>
            {user.avatarUrl && <img src={user.avatarUrl} alt="" style={{ width: 28, height: 28, borderRadius: '50%', border: '1px solid rgba(255,255,255,0.15)' }} />}
            {!user.avatarUrl && <div style={{ width: 28, height: 28, borderRadius: '50%', background: 'rgba(79,208,138,0.2)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}><GitBranch size={14} style={{ color: '#4fd08a' }} /></div>}
            <div style={{ minWidth: 0 }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: '#e2e8f0', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{user.username}</div>
              <div style={{ fontSize: '11px', color: '#4fd08a', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <CheckCircle2 size={11} /> Connected
              </div>
            </div>
          </div>
          <button
            onClick={handleLogout}
            disabled={loading}
            style={{
              padding: '6px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.12)',
              background: 'transparent', color: '#94a3b8', cursor: 'pointer', fontSize: '11px',
              display: 'flex', alignItems: 'center', gap: '4px', flexShrink: 0,
            }}
          >
            {loading ? <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> : <LogOut size={12} />}
            Disconnect
          </button>
        </div>
        {successMsg && (
          <div style={{ marginTop: '8px', padding: '8px 12px', borderRadius: '6px', background: 'rgba(79,208,138,0.1)', border: '1px solid rgba(79,208,138,0.3)', fontSize: '12px', color: '#4fd08a', display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
            <CheckCircle2 size={14} style={{ flexShrink: 0, marginTop: '1px' }} />
            <span>{successMsg}</span>
          </div>
        )}
        <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
      </div>
    );
  }

  return (
    <div>
      <button
        onClick={handleLogin}
        disabled={loading}
        style={{
          width: '100%', padding: '12px 16px', borderRadius: '8px', border: 'none',
          background: '#24292e', color: 'white', cursor: 'pointer', fontSize: '14px', fontWeight: 600,
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px',
        }}
      >
        <GitBranch size={18} />
        Login with GitHub
      </button>
      {error && (
        <div style={{ marginTop: '8px', padding: '8px 12px', borderRadius: '6px', background: 'rgba(255,107,107,0.1)', border: '1px solid rgba(255,107,107,0.3)', fontSize: '12px', color: '#ff6b6b', display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
          <AlertCircle size={14} style={{ flexShrink: 0, marginTop: '1px' }} />
          <span>{error}</span>
        </div>
      )}
      {successMsg && (
        <div style={{ marginTop: '8px', padding: '8px 12px', borderRadius: '6px', background: 'rgba(79,208,138,0.1)', border: '1px solid rgba(79,208,138,0.3)', fontSize: '12px', color: '#4fd08a', display: 'flex', alignItems: 'flex-start', gap: '6px' }}>
          <CheckCircle2 size={14} style={{ flexShrink: 0, marginTop: '1px' }} />
          <span>{successMsg}</span>
        </div>
      )}
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
