import { useState, useEffect } from 'react';
import {
  Cloud, Server, Database, Globe, Loader2, Check, AlertCircle,
  ExternalLink, Copy, RefreshCw, Settings, ChevronDown, ChevronRight,
  Package, GitBranch, Shield, Zap, X, Eye, EyeOff,
} from 'lucide-react';

const API_URL = 'http://localhost:4000';

function DeploymentDashboard({ projectId, projectName, repoUrl, branch }) {
  const [analysis, setAnalysis] = useState(null);
  const [deployments, setDeployments] = useState({});
  const [loading, setLoading] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedServices, setExpandedServices] = useState({});
  const [showEnvVars, setShowEnvVars] = useState(false);

  // Analyze project tech stack
  async function handleAnalyze() {
    setAnalyzing(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/analyze-project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ projectId, repoUrl, branch }),
      });
      if (!response.ok) throw new Error('Analysis failed');
      const data = await response.json();
      setAnalysis(data);
    } catch (err) {
      setError(err.message);
    } finally {
      setAnalyzing(false);
    }
  }

  // Deploy frontend
  async function deployFrontend() {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/deploy/frontend`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId,
          projectName,
          repoUrl,
          branch,
          framework: analysis?.frontend?.framework,
        }),
      });
      if (!response.ok) throw new Error('Frontend deployment failed');
      const data = await response.json();
      setDeployments((prev) => ({ ...prev, frontend: data }));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Deploy backend
  async function deployBackend() {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/deploy/backend`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId,
          projectName,
          repoUrl,
          branch,
          framework: analysis?.backend?.framework,
          port: 5000,
        }),
      });
      if (!response.ok) throw new Error('Backend deployment failed');
      const data = await response.json();
      setDeployments((prev) => ({ ...prev, backend: data }));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Deploy database
  async function deployDatabase() {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch(`${API_URL}/deploy/database`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          projectId,
          projectName,
          dbType: analysis?.database?.type,
          region: 'us-east-1',
        }),
      });
      if (!response.ok) throw new Error('Database deployment failed');
      const data = await response.json();
      setDeployments((prev) => ({ ...prev, database: data }));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  // Get deployment status
  async function getStatus(service) {
    try {
      const response = await fetch(`${API_URL}/deploy/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ service, deploymentId: deployments[service]?.id }),
      });
      if (!response.ok) throw new Error('Status check failed');
      const data = await response.json();
      setDeployments((prev) => ({ ...prev, [service]: data }));
    } catch (err) {
      setError(err.message);
    }
  }

  const toggleService = (service) => {
    setExpandedServices((prev) => ({ ...prev, [service]: !prev[service] }));
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div style={{ padding: '20px', maxWidth: '1200px' }}>
      <div style={{ display: 'flex', gap: '16px', marginBottom: '24px', alignItems: 'center' }}>
        <Cloud size={24} style={{ color: '#007bff' }} />
        <div>
          <h2 style={{ margin: '0 0 4px 0' }}>Deployment Dashboard</h2>
          <p style={{ margin: 0, fontSize: '13px', color: '#999' }}>
            Deploy {projectName} to Vercel, Render, and Railway — all free tier ✨
          </p>
        </div>
      </div>

      {error && (
        <div
          style={{
            padding: '12px 16px',
            background: 'rgba(255,68,68,0.1)',
            border: '1px solid rgba(255,68,68,0.3)',
            borderRadius: '8px',
            marginBottom: '16px',
            display: 'flex',
            gap: '12px',
            alignItems: 'center',
            color: '#ff4444',
            fontSize: '13px',
          }}
        >
          <AlertCircle size={16} />
          {error}
          <button
            onClick={() => setError(null)}
            style={{
              marginLeft: 'auto',
              background: 'none',
              border: 'none',
              color: '#ff4444',
              cursor: 'pointer',
              padding: '0',
            }}
          >
            <X size={16} />
          </button>
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '20px', borderBottom: '1px solid #333' }}>
        {['overview', 'frontend', 'backend', 'database', 'settings'].map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              padding: '12px 16px',
              background: activeTab === tab ? '#007bff' : 'transparent',
              border: 'none',
              color: activeTab === tab ? '#fff' : '#999',
              cursor: 'pointer',
              borderRadius: '6px 6px 0 0',
              fontSize: '13px',
              fontWeight: activeTab === tab ? '600' : '400',
              textTransform: 'capitalize',
            }}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
          {/* Analysis Card */}
          <div
            style={{
              padding: '16px',
              background: '#1a1a1a',
              border: '1px solid #333',
              borderRadius: '8px',
              gridColumn: '1 / -1',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <h3 style={{ margin: 0, fontSize: '14px', fontWeight: '600' }}>Tech Stack Analysis</h3>
              <button
                onClick={handleAnalyze}
                disabled={analyzing}
                style={{
                  padding: '6px 12px',
                  background: '#007bff',
                  border: 'none',
                  color: '#fff',
                  borderRadius: '4px',
                  cursor: 'pointer',
                  fontSize: '12px',
                  display: 'flex',
                  gap: '6px',
                  alignItems: 'center',
                }}
              >
                {analyzing ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Zap size={14} />}
                {analyzing ? 'Analyzing...' : 'Analyze Now'}
              </button>
            </div>

            {analysis ? (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
                {/* Frontend */}
                <div
                  style={{
                    padding: '12px',
                    background: '#252525',
                    borderRadius: '6px',
                    border: '1px solid #333',
                  }}
                >
                  <div style={{ fontSize: '11px', color: '#999', marginBottom: '4px' }}>Frontend</div>
                  {analysis.frontend ? (
                    <>
                      <div
                        style={{
                          fontSize: '13px',
                          fontWeight: '600',
                          color: '#fff',
                          marginBottom: '4px',
                        }}
                      >
                        {analysis.frontend.framework}
                      </div>
                      <div style={{ fontSize: '11px', color: '#ccc' }}>{analysis.frontend.version || 'Latest'}</div>
                      <div
                        style={{
                          fontSize: '11px',
                          color: '#0f9',
                          marginTop: '4px',
                          padding: '4px 8px',
                          background: 'rgba(0,255,153,0.1)',
                          borderRadius: '3px',
                          display: 'inline-block',
                        }}
                      >
                        Deploy to Vercel
                      </div>
                    </>
                  ) : (
                    <div style={{ fontSize: '12px', color: '#999' }}>Not detected</div>
                  )}
                </div>

                {/* Backend */}
                <div
                  style={{
                    padding: '12px',
                    background: '#252525',
                    borderRadius: '6px',
                    border: '1px solid #333',
                  }}
                >
                  <div style={{ fontSize: '11px', color: '#999', marginBottom: '4px' }}>Backend</div>
                  {analysis.backend ? (
                    <>
                      <div style={{ fontSize: '13px', fontWeight: '600', color: '#fff', marginBottom: '4px' }}>
                        {analysis.backend.framework}
                      </div>
                      <div style={{ fontSize: '11px', color: '#ccc' }}>{analysis.backend.version || 'Latest'}</div>
                      <div
                        style={{
                          fontSize: '11px',
                          color: '#0f9',
                          marginTop: '4px',
                          padding: '4px 8px',
                          background: 'rgba(0,255,153,0.1)',
                          borderRadius: '3px',
                          display: 'inline-block',
                        }}
                      >
                        Deploy to Render
                      </div>
                    </>
                  ) : (
                    <div style={{ fontSize: '12px', color: '#999' }}>Not detected</div>
                  )}
                </div>

                {/* Database */}
                <div
                  style={{
                    padding: '12px',
                    background: '#252525',
                    borderRadius: '6px',
                    border: '1px solid #333',
                  }}
                >
                  <div style={{ fontSize: '11px', color: '#999', marginBottom: '4px' }}>Database</div>
                  {analysis.database ? (
                    <>
                      <div style={{ fontSize: '13px', fontWeight: '600', color: '#fff', marginBottom: '4px' }}>
                        {analysis.database.type}
                      </div>
                      <div style={{ fontSize: '11px', color: '#ccc' }}>
                        {analysis.database.version || 'Latest'}
                      </div>
                      <div
                        style={{
                          fontSize: '11px',
                          color: '#0f9',
                          marginTop: '4px',
                          padding: '4px 8px',
                          background: 'rgba(0,255,153,0.1)',
                          borderRadius: '3px',
                          display: 'inline-block',
                        }}
                      >
                        Deploy to Railway
                      </div>
                    </>
                  ) : (
                    <div style={{ fontSize: '12px', color: '#999' }}>Not detected</div>
                  )}
                </div>
              </div>
            ) : (
              <div style={{ fontSize: '13px', color: '#999', padding: '24px', textAlign: 'center' }}>
                Click "Analyze Now" to detect your project's tech stack
              </div>
            )}
          </div>

          {/* Deployment Status */}
          {analysis && (
            <>
              {/* Frontend Status */}
              {analysis.frontend && (
                <div
                  style={{
                    padding: '16px',
                    background: '#1a1a1a',
                    border: '1px solid #333',
                    borderRadius: '8px',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '12px',
                      cursor: 'pointer',
                    }}
                    onClick={() => toggleService('frontend')}
                  >
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      {expandedServices.frontend ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      <Globe size={16} style={{ color: '#0f9' }} />
                      <span style={{ fontSize: '13px', fontWeight: '600' }}>Frontend (Vercel)</span>
                    </div>
                    {deployments.frontend?.status === 'deployed' && (
                      <Check size={16} style={{ color: '#0f9' }} />
                    )}
                  </div>

                  {expandedServices.frontend && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {deployments.frontend ? (
                        <>
                          <div
                            style={{
                              fontSize: '11px',
                              padding: '8px 12px',
                              background: '#252525',
                              borderRadius: '4px',
                              color: '#ccc',
                            }}
                          >
                            <div style={{ marginBottom: '4px' }}>Status: {deployments.frontend.status}</div>
                            {deployments.frontend.url && (
                              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                <span style={{ fontSize: '10px', color: '#999', wordBreak: 'break-all' }}>
                                  {deployments.frontend.url}
                                </span>
                                <button
                                  onClick={() => copyToClipboard(deployments.frontend.url)}
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    color: '#0f9',
                                    cursor: 'pointer',
                                    padding: '0',
                                  }}
                                >
                                  <Copy size={12} />
                                </button>
                              </div>
                            )}
                          </div>
                          <button
                            onClick={() => getStatus('frontend')}
                            style={{
                              padding: '6px 12px',
                              background: '#007bff',
                              border: 'none',
                              color: '#fff',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              fontSize: '11px',
                            }}
                          >
                            Refresh Status
                          </button>
                        </>
                      ) : (
                        <button
                          onClick={deployFrontend}
                          disabled={loading}
                          style={{
                            padding: '8px 12px',
                            background: '#0f9',
                            border: 'none',
                            color: '#000',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: '600',
                            display: 'flex',
                            gap: '6px',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          {loading ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Cloud size={14} />}
                          {loading ? 'Deploying...' : 'Deploy Frontend'}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Backend Status */}
              {analysis.backend && (
                <div
                  style={{
                    padding: '16px',
                    background: '#1a1a1a',
                    border: '1px solid #333',
                    borderRadius: '8px',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '12px',
                      cursor: 'pointer',
                    }}
                    onClick={() => toggleService('backend')}
                  >
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      {expandedServices.backend ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      <Server size={16} style={{ color: '#0f9' }} />
                      <span style={{ fontSize: '13px', fontWeight: '600' }}>Backend (Render)</span>
                    </div>
                    {deployments.backend?.status === 'deployed' && (
                      <Check size={16} style={{ color: '#0f9' }} />
                    )}
                  </div>

                  {expandedServices.backend && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {deployments.backend ? (
                        <>
                          <div
                            style={{
                              fontSize: '11px',
                              padding: '8px 12px',
                              background: '#252525',
                              borderRadius: '4px',
                              color: '#ccc',
                            }}
                          >
                            <div style={{ marginBottom: '4px' }}>Status: {deployments.backend.status}</div>
                            {deployments.backend.url && (
                              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                <span style={{ fontSize: '10px', color: '#999', wordBreak: 'break-all' }}>
                                  {deployments.backend.url}
                                </span>
                                <button
                                  onClick={() => copyToClipboard(deployments.backend.url)}
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    color: '#0f9',
                                    cursor: 'pointer',
                                    padding: '0',
                                  }}
                                >
                                  <Copy size={12} />
                                </button>
                              </div>
                            )}
                          </div>
                          <button
                            onClick={() => getStatus('backend')}
                            style={{
                              padding: '6px 12px',
                              background: '#007bff',
                              border: 'none',
                              color: '#fff',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              fontSize: '11px',
                            }}
                          >
                            Refresh Status
                          </button>
                        </>
                      ) : (
                        <button
                          onClick={deployBackend}
                          disabled={loading}
                          style={{
                            padding: '8px 12px',
                            background: '#0f9',
                            border: 'none',
                            color: '#000',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: '600',
                            display: 'flex',
                            gap: '6px',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          {loading ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Cloud size={14} />}
                          {loading ? 'Deploying...' : 'Deploy Backend'}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Database Status */}
              {analysis.database && (
                <div
                  style={{
                    padding: '16px',
                    background: '#1a1a1a',
                    border: '1px solid #333',
                    borderRadius: '8px',
                  }}
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      marginBottom: '12px',
                      cursor: 'pointer',
                    }}
                    onClick={() => toggleService('database')}
                  >
                    <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                      {expandedServices.database ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
                      <Database size={16} style={{ color: '#0f9' }} />
                      <span style={{ fontSize: '13px', fontWeight: '600' }}>Database (Railway)</span>
                    </div>
                    {deployments.database?.status === 'deployed' && (
                      <Check size={16} style={{ color: '#0f9' }} />
                    )}
                  </div>

                  {expandedServices.database && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {deployments.database ? (
                        <>
                          <div
                            style={{
                              fontSize: '11px',
                              padding: '8px 12px',
                              background: '#252525',
                              borderRadius: '4px',
                              color: '#ccc',
                            }}
                          >
                            <div style={{ marginBottom: '4px' }}>Status: {deployments.database.status}</div>
                            {deployments.database.connectionString && (
                              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                <span
                                  style={{
                                    fontSize: '10px',
                                    color: '#999',
                                    wordBreak: 'break-all',
                                    fontFamily: 'monospace',
                                  }}
                                >
                                  {showEnvVars ? deployments.database.connectionString : '•••••••'}
                                </span>
                                <button
                                  onClick={() => setShowEnvVars(!showEnvVars)}
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    color: '#0f9',
                                    cursor: 'pointer',
                                    padding: '0',
                                  }}
                                >
                                  {showEnvVars ? <EyeOff size={12} /> : <Eye size={12} />}
                                </button>
                                <button
                                  onClick={() => copyToClipboard(deployments.database.connectionString)}
                                  style={{
                                    background: 'none',
                                    border: 'none',
                                    color: '#0f9',
                                    cursor: 'pointer',
                                    padding: '0',
                                  }}
                                >
                                  <Copy size={12} />
                                </button>
                              </div>
                            )}
                          </div>
                          <button
                            onClick={() => getStatus('database')}
                            style={{
                              padding: '6px 12px',
                              background: '#007bff',
                              border: 'none',
                              color: '#fff',
                              borderRadius: '4px',
                              cursor: 'pointer',
                              fontSize: '11px',
                            }}
                          >
                            Refresh Status
                          </button>
                        </>
                      ) : (
                        <button
                          onClick={deployDatabase}
                          disabled={loading}
                          style={{
                            padding: '8px 12px',
                            background: '#0f9',
                            border: 'none',
                            color: '#000',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '12px',
                            fontWeight: '600',
                            display: 'flex',
                            gap: '6px',
                            alignItems: 'center',
                            justifyContent: 'center',
                          }}
                        >
                          {loading ? <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} /> : <Cloud size={14} />}
                          {loading ? 'Deploying...' : 'Deploy Database'}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Other tabs - placeholder content */}
      {['frontend', 'backend', 'database', 'settings'].includes(activeTab) && (
        <div
          style={{
            padding: '40px 20px',
            textAlign: 'center',
            color: '#999',
            fontSize: '13px',
          }}
        >
          {activeTab} tab content coming soon...
        </div>
      )}

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

export default DeploymentDashboard;
