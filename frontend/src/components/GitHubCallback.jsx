import { useEffect } from 'react';
import { Loader2 } from 'lucide-react';

export default function GitHubCallback() {
  useEffect(() => {
    // Legacy route — redirect to root. Session cookie is already set by backend.
    window.location.replace('/');
  }, []);

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      minHeight: '60vh', gap: '20px', padding: '40px',
    }}>
      <Loader2 size={48} style={{ color: '#a78bfa', animation: 'spin 1s linear infinite' }} />
      <h2 style={{ margin: 0, fontSize: '18px', color: '#cbd5e1' }}>Redirecting...</h2>
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
