import { useState, useEffect } from 'react';
import {
  Folder, Plus, GitBranch, Settings, CheckCircle2,
  AlertTriangle, X, ExternalLink, Copy, Check, Cloud,
  Zap, Shield, TrendingUp, Calendar, Code2, GitCompare,
  Eye, EyeOff, Clock, BarChart2, RefreshCw, Play, Loader2,
} from 'lucide-react';

const API_URL = 'http://localhost:4000';

function formatDate(dateStr) {
  if (!dateStr) return 'Never';
  const d = new Date(dateStr);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function severityClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'sev-critical';
  if (s === 'high') return 'sev-high';
  if (s === 'medium') return 'sev-medium';
  return 'sev-low';
}

const CRITICAL_FALLBACK = { background: 'rgba(255,0,60,0.15)', color: '#ff3c5f', border: '1px solid rgba(255,0,60,0.4)' };

// Connect Repository Modal
function ConnectRepoModal({ isOpen, onClose, onConnect }) {
  const [platform, setPlatform] = useState('github');
  const [projectName, setProjectName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [token, setToken] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [autoScan, setAutoScan] = useState(true);
  const [scanFrequency, setScanFrequency] = useState('daily');
  const [connecting, setConnecting] = useState(false);

  async function handleConnect() {
    if (!projectName.trim() || !repoUrl.trim() || !token.trim()) {
      alert('Please fill in all fields');
      return;
    }

    setConnecting(true);
    try {
      const payload = {
        name: projectName,
        platform: platform === 'github' ? 'GitHub' : 'GitLab',
        repos: [{ name: projectName, url: repoUrl, branch }],
        settings: { autoScan, scanFrequency },
        token, // Backend encrypts this before storing (see tokenCrypto.js)
      };

      await onConnect(payload);
      setProjectName('');
      setRepoUrl('');
      setToken('');
      onClose();
    } catch (err) {
      alert('Failed to connect repository: ' + err.message);
    } finally {
      setConnecting(false);
    }
  }

  if (!isOpen) return null;

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="panel how-it-works-modal" onClick={(e) => e.stopPropagation()} style={{ maxWidth: '540px' }}>
        <div className="panel-head">
          <div className="panel-icon"><Cloud size={18} /></div>
          <div><h2>Connect Repository</h2></div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '4px 0' }}>
          {/* Platform selector */}
          <div>
            <div className="field-label">Platform</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '8px' }}>
              {[
                { key: 'github', label: 'GitHub', icon: GitBranch },
                { key: 'gitlab', label: 'GitLab', icon: Cloud },
              ].map((p) => (
                <button
                  key={p.key}
                  onClick={() => setPlatform(p.key)}
                  style={{
                    padding: '10px 14px',
                    border: platform === p.key ? '1px solid #3ba7f0' : '1px solid var(--border)',
                    background: platform === p.key ? 'rgba(59,167,240,0.1)' : 'var(--panel-2)',
                    borderRadius: '8px',
                    color: 'var(--text)',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    fontSize: '13px',
                    fontWeight: 500,
                  }}
                >
                  <p.icon size={16} /> {p.label}
                </button>
              ))}
            </div>
          </div>

          {/* Project name */}
          <div>
            <div className="field-label">Project Name</div>
            <input
              type="text"
              className="code-input"
              style={{ height: 'auto', padding: '8px 12px', marginTop: '6px' }}
              placeholder="e.g., securecode-app"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
            />
          </div>

          {/* Repository URL */}
          <div>
            <div className="field-label">Repository URL</div>
            <input
              type="text"
              className="code-input"
              style={{ height: 'auto', padding: '8px 12px', marginTop: '6px' }}
              placeholder={platform === 'github' ? 'github.com/owner/repo' : 'gitlab.com/owner/repo'}
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
            />
          </div>

          {/* Branch */}
          <div>
            <div className="field-label">Default Branch</div>
            <input
              type="text"
              className="code-input"
              style={{ height: 'auto', padding: '8px 12px', marginTop: '6px' }}
              placeholder="main"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
            />
          </div>

          {/* Token */}
          <div>
            <div className="field-label">
              {platform === 'github' ? 'GitHub Personal Access Token' : 'GitLab Personal Access Token'}
            </div>
            <div style={{ position: 'relative', marginTop: '6px' }}>
              <input
                type={showToken ? 'text' : 'password'}
                className="code-input"
                style={{ height: 'auto', padding: '8px 12px', paddingRight: '36px' }}
                placeholder="ghp_xxxxxxxxxxxxxxxxxx"
                value={token}
                onChange={(e) => setToken(e.target.value)}
              />
              <button
                className="icon-btn"
                style={{
                  position: 'absolute',
                  right: '6px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  width: '28px',
                  height: '28px',
                }}
                onClick={() => setShowToken(!showToken)}
                aria-label="Toggle token visibility"
              >
                {showToken ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
            <p style={{ fontSize: '11px', color: 'var(--text-faint)', marginTop: '6px' }}>
              Create a PAT with repo access at{' '}
              <a href={platform === 'github' ? 'https://github.com/settings/tokens' : 'https://gitlab.com/-/user_settings/personal_access_tokens'} target="_blank" rel="noreferrer" style={{ color: '#7ec3f5' }}>
                {platform === 'github' ? 'github.com/settings/tokens' : 'gitlab.com/user_settings/personal_access_tokens'}
              </a>
            </p>
          </div>

          {/* Auto-scan settings */}
          <div style={{ paddingTop: '8px', borderTop: '1px solid var(--border)' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '12px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={autoScan}
                onChange={(e) => setAutoScan(e.target.checked)}
                style={{ width: '16px', height: '16px', accentColor: '#7c6ee8' }}
              />
              <span style={{ fontSize: '13px', fontWeight: 500 }}>Enable automatic scanning</span>
            </label>

            {autoScan && (
              <div>
                <div className="field-label">Scan Frequency</div>
                <select
                  className="code-input"
                  style={{ height: 'auto', padding: '8px 12px', marginTop: '6px' }}
                  value={scanFrequency}
                  onChange={(e) => setScanFrequency(e.target.value)}
                >
                  <option value="on-push">On every push</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                </select>
              </div>
            )}
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', gap: '10px', paddingTop: '8px' }}>
            <button className="scan-btn" style={{ flex: 1 }} onClick={handleConnect} disabled={connecting}>
              {connecting ? 'Connecting…' : '+ Connect Repository'}
            </button>
            <button
              className="text-btn"
              style={{ padding: '10px 14px', borderRadius: '8px', background: 'var(--panel-2)' }}
              onClick={onClose}
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// Project Card — shows security score, repos, last scan, remediation progress
function ProjectCard({ project, onSelect, onRescan, isScanning }) {
  const scoreColor = project.securityScore >= 80 ? '#4fd08a' : project.securityScore >= 60 ? '#e8a33d' : '#e2504a';

  return (
    <div
      className="finding-card"
      style={{ cursor: 'pointer' }}
      onClick={() => onSelect(project)}
    >
      <div className="finding-top">
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1 }}>
          <div style={{
            width: '32px',
            height: '32px',
            borderRadius: '6px',
            background: '#12283a',
            color: '#3ba7f0',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}>
            <Folder size={16} />
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: '13.5px' }}>{project.name}</div>
            <div style={{ fontSize: '11px', color: 'var(--text-faint)', marginTop: '2px' }}>
              {project.platform} · {project.repos[0]?.branch || 'main'}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '18px', fontWeight: 700, color: scoreColor }}>
              {project.securityScore}
            </div>
            <div style={{ fontSize: '10px', color: 'var(--text-faint)' }}>Score</div>
          </div>
        </div>
      </div>

      {/* Issues summary */}
      <div className="summary-row" style={{ marginTop: '10px', marginBottom: '0' }}>
        {project.critical > 0 && (
          <div className="summary-chip" style={{ ...CRITICAL_FALLBACK, flex: 0 }}>
            {project.critical} critical
          </div>
        )}
        {project.high > 0 && (
          <div className="summary-chip sev-high" style={{ flex: 0 }}>
            {project.high} high
          </div>
        )}
        <div className="summary-chip sev-medium" style={{ flex: 0 }}>
          {project.medium} medium
        </div>
        <div className="summary-chip sev-low" style={{ flex: 0 }}>
          {project.low} low
        </div>
      </div>

      {/* Remediation progress */}
      <div style={{ marginTop: '10px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px', fontSize: '12px' }}>
          <span style={{ color: 'var(--text-faint)' }}>Remediation Progress</span>
          <span style={{ fontWeight: 600, color: '#a98cf0' }}>{project.remediationProgress}%</span>
        </div>
        <div className="dash-cat-track" style={{ height: '6px' }}>
          <div
            className="dash-cat-fill"
            style={{
              width: `${project.remediationProgress}%`,
              background: project.remediationProgress >= 80 ? '#4fd08a' : project.remediationProgress >= 50 ? '#e8a33d' : '#e2504a',
            }}
          />
        </div>
      </div>

      {/* Last scan */}
      <div style={{ marginTop: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: 'var(--text-faint)' }}>
        <span>Last scanned: {formatDate(project.lastScan)}</span>
        <button
          className="text-btn"
          onClick={(e) => {
            e.stopPropagation();
            if (!isScanning) onRescan(project);
          }}
          disabled={isScanning}
          style={{ padding: '4px 8px', fontSize: '11px', opacity: isScanning ? 0.6 : 1, cursor: isScanning ? 'default' : 'pointer' }}
        >
          {isScanning ? (
            <>
              <Loader2 size={12} className="spin" /> Scanning…
            </>
          ) : (
            <>
              <RefreshCw size={12} /> Rescan
            </>
          )}
        </button>
      </div>
    </div>
  );
}

// Project Detail View — shows dashboard, PR status, remediation tracker
function ProjectDetailView({ project, onBack, onAutoScanToggle }) {
  const [autoScan, setAutoScan] = useState(project.autoScanEnabled);
  const [scans, setScans] = useState([]);
  const [scansLoading, setScansLoading] = useState(true);

  const scoreLabel = project.securityScore >= 80 ? 'Excellent' : project.securityScore >= 60 ? 'Good' : 'Poor';
  const scoreColor = project.securityScore >= 80 ? '#4fd08a' : project.securityScore >= 60 ? '#e8a33d' : '#e2504a';

  useEffect(() => {
    let cancelled = false;
    async function loadScans() {
      setScansLoading(true);
      try {
        const res = await fetch(`${API_URL}/projects/${project.id}/scans`);
        const data = await res.json();
        if (!cancelled) setScans(data.scans || []);
      } catch (err) {
        console.error('Failed to load scan history:', err);
      } finally {
        if (!cancelled) setScansLoading(false);
      }
    }
    loadScans();
    return () => { cancelled = true; };
  }, [project.id]);

  function handleAutoScanToggle() {
    setAutoScan(!autoScan);
    onAutoScanToggle(project.id, !autoScan);
  }

  return (
    <>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
        <button className="icon-btn" onClick={onBack} aria-label="Back">
          <X size={16} />
        </button>
        <div style={{ flex: 1 }}>
          <h2 style={{ margin: '0 0 4px', fontSize: '18px' }}>{project.name}</h2>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-faint)' }}>
            {project.platform} · {project.repos[0]?.url}
          </p>
        </div>
      </div>

      {/* Dashboard grid */}
      <div className="dash-mid-grid" style={{ marginBottom: '16px' }}>
        <div className="dash-sub-panel">
          <h3>Security Score</h3>
          <div className="dash-donut-row">
            <svg width="100" height="100" viewBox="0 0 42 42">
              <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
              <circle
                cx="21" cy="21" r="15.9" fill="transparent"
                stroke={scoreColor} strokeWidth="6"
                strokeDasharray={`${project.securityScore} ${100 - project.securityScore}`}
                strokeDashoffset="25"
              />
              <text x="21" y="19" textAnchor="middle" fontSize="8" fill="#e8e9ee" fontWeight="700">
                {project.securityScore}
              </text>
              <text x="21" y="26" textAnchor="middle" fontSize="3.4" fill="#5c5f6d">
                /100
              </text>
            </svg>
            <div className="dash-stat-sub" style={{ color: scoreColor, fontWeight: 600 }}>{scoreLabel}</div>
          </div>
        </div>

        <div className="dash-sub-panel">
          <h3>Severity Breakdown</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div className="dash-cat-row">
              <span className="dash-dot" style={{ background: '#e2504a' }} />
              <div className="dash-cat-label">Critical</div>
              <div className="dash-cat-count">{project.critical}</div>
            </div>
            <div className="dash-cat-row">
              <span className="dash-dot" style={{ background: '#e8a33d' }} />
              <div className="dash-cat-label">High</div>
              <div className="dash-cat-count">{project.high}</div>
            </div>
            <div className="dash-cat-row">
              <span className="dash-dot" style={{ background: '#d9c94f' }} />
              <div className="dash-cat-label">Medium</div>
              <div className="dash-cat-count">{project.medium}</div>
            </div>
            <div className="dash-cat-row">
              <span className="dash-dot" style={{ background: '#4fd08a' }} />
              <div className="dash-cat-label">Low</div>
              <div className="dash-cat-count">{project.low}</div>
            </div>
          </div>
        </div>

        <div className="dash-sub-panel">
          <h3>Remediation Progress</h3>
          <div style={{ marginTop: '10px' }}>
            <div style={{ marginBottom: '8px' }}>
              <svg width="100%" height="80" viewBox="0 0 140 80" preserveAspectRatio="none">
                <rect x="0" y="60" width={project.remediationProgress * 1.4} height="20" fill="#a98cf0" rx="4" />
                <text x={project.remediationProgress * 0.7} y="75" textAnchor="middle" fontSize="12" fill="#fff" fontWeight="700">
                  {project.remediationProgress}%
                </text>
              </svg>
            </div>
            <div style={{ display: 'flex', gap: '16px', justifyContent: 'space-between', fontSize: '11.5px', color: 'var(--text-faint)' }}>
              <span>Fixed: {Math.round((project.totalIssues * project.remediationProgress) / 100)}</span>
              <span>Remaining: {project.totalIssues - Math.round((project.totalIssues * project.remediationProgress) / 100)}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="content-grid" style={{ marginBottom: '16px' }}>
        {/* Auto-scan settings */}
        <section className="panel">
          <div className="panel-head">
            <div className="panel-icon"><Zap size={18} /></div>
            <div><h2 style={{ fontSize: '16px' }}>Auto-Scan Settings</h2></div>
          </div>

          <div className="settings-row" style={{ borderBottom: 'none', marginBottom: '0', paddingBottom: '0' }}>
            <div>
              <div className="settings-label">Automatic Scanning</div>
              <div className="settings-sub">Scan on push, PR, or on schedule</div>
            </div>
            <button
              className={`toggle ${autoScan ? 'on' : ''}`}
              onClick={handleAutoScanToggle}
              aria-label="Toggle auto-scan"
            >
              <span className="toggle-knob" />
            </button>
          </div>

          {autoScan && (
            <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid var(--border)' }}>
              <div className="settings-label" style={{ marginBottom: '6px' }}>Scan Frequency</div>
              <select
                className="code-input"
                style={{ height: 'auto', padding: '8px 12px' }}
                defaultValue={project.autoScanFrequency}
              >
                <option value="on-push">On every push</option>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
              </select>
            </div>
          )}
        </section>

        {/* PR Status */}
        <section className="panel">
          <div className="panel-head">
            <div className="panel-icon"><GitCompare size={18} /></div>
            <div><h2 style={{ fontSize: '16px' }}>Remediation PRs ({project.prs.length})</h2></div>
          </div>

          {project.prs.length === 0 ? (
            <p className="empty-sub">No PRs created yet. Once issues are detected, fix PRs will be suggested.</p>
          ) : (
            <div className="findings-list">
              {project.prs.map((pr) => (
                <div className="finding-card" key={pr.id}>
                  <div className="finding-top">
                    <span style={{ fontWeight: 600, fontSize: '13px' }}>{pr.title}</span>
                    <span
                      className="sev-pill"
                      style={
                        pr.status === 'merged'
                          ? { background: '#12301f', color: '#4fd08a', border: '1px solid rgba(79,208,138,0.4)' }
                          : pr.status === 'open'
                          ? { background: 'rgba(169,140,240,0.15)', color: '#a98cf0', border: '1px solid rgba(169,140,240,0.4)' }
                          : { background: 'rgba(217,201,79,0.15)', color: '#d9c94f', border: '1px solid rgba(217,201,79,0.4)' }
                      }
                    >
                      {pr.status === 'merged' ? '✓ Merged' : pr.status === 'open' ? 'Open' : 'Draft'}
                    </span>
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-faint)', marginTop: '6px' }}>
                    {formatDate(pr.createdAt)}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>

      {/* Remediation Tracker */}
      <section className="panel" style={{ marginBottom: '16px' }}>
        <div className="panel-head">
          <div className="panel-icon"><CheckCircle2 size={18} /></div>
          <div><h2 style={{ fontSize: '16px' }}>Remediation Checklist</h2></div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {[
            { label: 'Fix critical vulnerabilities', priority: 'critical', complete: project.critical === 0 },
            { label: 'Address high severity issues', priority: 'high', complete: project.high <= 2 },
            { label: 'Review and update dependencies', priority: 'medium', complete: project.remediationProgress >= 50 },
            { label: 'Enable HTTPS & security headers', priority: 'medium', complete: project.remediationProgress >= 70 },
            { label: 'Implement monitoring & logging', priority: 'low', complete: project.remediationProgress >= 90 },
          ].map((item, i) => (
            <div
              key={i}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '10px',
                background: item.complete ? 'rgba(79,208,138,0.08)' : 'transparent',
                borderRadius: '8px',
                borderLeft: `3px solid ${item.complete ? '#4fd08a' : 'var(--border)'}`,
              }}
            >
              <input
                type="checkbox"
                checked={item.complete}
                onChange={() => {}}
                style={{ width: '16px', height: '16px', accentColor: '#7c6ee8', cursor: 'pointer' }}
              />
              <span style={{ flex: 1, fontSize: '13px' }}>{item.label}</span>
              <span
                className="chip"
                style={{
                  fontSize: '10px',
                  padding: '2px 8px',
                  background:
                    item.priority === 'critical'
                      ? 'rgba(255,0,60,0.15)'
                      : item.priority === 'high'
                      ? 'rgba(232,163,61,0.15)'
                      : 'rgba(217,201,79,0.15)',
                  color:
                    item.priority === 'critical'
                      ? '#ff3c5f'
                      : item.priority === 'high'
                      ? '#e8a33d'
                      : '#d9c94f',
                  border: 'none',
                }}
              >
                {item.priority}
              </span>
            </div>
          ))}
        </div>
      </section>

      {/* Recent Scans */}
      <section className="panel">
        <div className="panel-head">
          <div className="panel-icon"><BarChart2 size={18} /></div>
          <div><h2 style={{ fontSize: '16px' }}>Scan History</h2></div>
        </div>

        {scansLoading ? (
          <p className="empty-sub">Loading scan history…</p>
        ) : scans.length === 0 ? (
          <p className="empty-sub">No scans yet. Run a rescan from the Projects list to populate history.</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {scans.map((scan) => (
              <div key={scan.id} className="dash-scan-row">
                <Clock size={14} style={{ opacity: 0.6, flexShrink: 0 }} />
                <div className="dash-scan-meta" style={{ flex: 1 }}>
                  <div className="dash-scan-name">{formatDate(scan.scannedAt)}</div>
                </div>
                {scan.status === 'in_progress' ? (
                  <span className="chip" style={{ fontSize: '11px' }}>Scanning…</span>
                ) : scan.status === 'failed' ? (
                  <span className="chip" style={{ fontSize: '11px', color: '#e2504a' }}>Failed</span>
                ) : (
                  <>
                    <span className="chip" style={{ fontSize: '11px' }}>
                      {(scan.critical || 0) + (scan.high || 0) + (scan.medium || 0) + (scan.low || 0)} issues
                    </span>
                    <span style={{ fontWeight: 600, color: '#a98cf0', fontSize: '12px' }}>
                      {scan.riskScore != null ? `${scan.riskScore}/100 risk` : '—'}
                    </span>
                  </>
                )}
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

// Main Projects Panel
export default function ProjectsPanel() {
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [scanningIds, setScanningIds] = useState(new Set());

  async function loadProjects() {
    try {
      const res = await fetch(`${API_URL}/projects`);
      const data = await res.json();
      setProjects(data.projects || []);
    } catch (err) {
      console.error('Failed to load projects:', err);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadProjects();
  }, []);

  async function handleConnect(payload) {
    const res = await fetch(`${API_URL}/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to connect repository');
    }
    await loadProjects();
  }

  async function handleAutoScanToggle(projectId, enabled) {
    try {
      await fetch(`${API_URL}/projects/${projectId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ autoScanEnabled: enabled }),
      });
      loadProjects();
    } catch (err) {
      console.error('Failed to update auto-scan setting:', err);
    }
  }

  async function handleRescan(project) {
    setScanningIds((prev) => new Set(prev).add(project.id));
    try {
      const res = await fetch(`${API_URL}/projects/${project.id}/scan`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to start scan');
      }

      // Poll every 3s until the scan leaves "in_progress"
      const poll = setInterval(async () => {
        try {
          const scansRes = await fetch(`${API_URL}/projects/${project.id}/scans`);
          const data = await scansRes.json();
          const latest = data.scans?.[0];
          if (latest && latest.status !== 'in_progress') {
            clearInterval(poll);
            setScanningIds((prev) => {
              const next = new Set(prev);
              next.delete(project.id);
              return next;
            });
            loadProjects();
          }
        } catch (pollErr) {
          console.error('Polling error:', pollErr);
        }
      }, 3000);
    } catch (err) {
      setScanningIds((prev) => {
        const next = new Set(prev);
        next.delete(project.id);
        return next;
      });
      alert('Failed to start scan: ' + err.message);
    }
  }

  if (selectedProject) {
    return (
      <section className="panel wide-panel">
        <ProjectDetailView
          project={selectedProject}
          onBack={() => setSelectedProject(null)}
          onAutoScanToggle={handleAutoScanToggle}
        />
      </section>
    );
  }

  return (
    <section className="panel wide-panel">
      <div className="panel-head">
        <div className="panel-icon"><Folder size={18} /></div>
        <div>
          <h2>Projects</h2>
          <p>Manage security scans across your repositories. Connect repos and track remediation progress.</p>
        </div>
        <button className="scan-btn" style={{ marginLeft: 'auto', padding: '8px 14px' }} onClick={() => setModalOpen(true)}>
          <Plus size={16} /> Connect Repository
        </button>
      </div>

      {loading ? (
        <p className="empty-sub">Loading projects…</p>
      ) : projects.length === 0 ? (
        <div className="empty-state">
          <Folder size={56} className="empty-icon" />
          <h3>No projects yet.</h3>
          <p className="empty-sub">Connect your first repository to start scanning and tracking security across your projects.</p>
          
        </div>
      ) : (
        <>
          {/* Stats grid */}
          <div className="dash-stats-grid" style={{ marginBottom: '16px', gridTemplateColumns: 'repeat(4, 1fr)' }}>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><Folder size={14} /></div>
              <div className="dash-stat-value">{projects.length}</div>
              <div className="dash-stat-sub">Total Projects</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head" style={{ color: '#e2504a' }}>Critical</div>
              <div className="dash-stat-value" style={{ color: '#e2504a' }}>
                {projects.reduce((sum, p) => sum + (p.critical || 0), 0)}
              </div>
              <div className="dash-stat-sub">Across all projects</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head" style={{ color: '#e8a33d' }}>High</div>
              <div className="dash-stat-value" style={{ color: '#e8a33d' }}>
                {projects.reduce((sum, p) => sum + (p.high || 0), 0)}
              </div>
              <div className="dash-stat-sub">Across all projects</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head" style={{ color: '#a98cf0' }}>Avg. Score</div>
              <div className="dash-stat-value" style={{ color: '#a98cf0' }}>
                {Math.round(projects.reduce((sum, p) => sum + (p.securityScore || 0), 0) / projects.length)}
              </div>
              <div className="dash-stat-sub">Security Score</div>
            </div>
          </div>

          {/* Projects grid */}
          <div className="findings-list">
            {projects.map((project) => (
              <ProjectCard
                key={project.id}
                project={project}
                onSelect={setSelectedProject}
                onRescan={handleRescan}
                isScanning={scanningIds.has(project.id)}
              />
            ))}
          </div>
        </>
      )}

      <ConnectRepoModal isOpen={modalOpen} onClose={() => setModalOpen(false)} onConnect={handleConnect} />
    </section>
  );
}