import { useState, useEffect, useRef, useMemo } from 'react';
import {
  Folder, FolderOpen, Plus, GitBranch, Settings, CheckCircle2,
  AlertTriangle, X, ExternalLink, Cloud, Shield, RefreshCw, Loader2,
  Eye, EyeOff, Clock, Download, Search, FileCode2,
  ChevronRight, ChevronDown, ChevronLeft, ArrowLeft, Lock, Globe, Bug, Trash2,
} from 'lucide-react';
// Pure vulnerability/tree logic lives in a shared module so the offline test
// (test_repo_details.mjs) exercises the exact code this UI runs.
import {
  SEV_META, SEV_ORDER, normSev, sevMeta, codeStartLine, diffLines,
  findingKey, computeTreeAggregates, buildFileTree, sortedChildren,
} from './vulnLogic';
import FolderScanResults from './components/FolderScanResults';
import DeploymentDashboard from './components/DeploymentDashboard';
import GitHubLogin from './components/GitHubLogin';
import GitHubRepoBrowser from './components/GitHubRepoBrowser';
import PRCreationModal from './components/PRCreationModal';

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

// ---------------------------------------------------------------------------
// Connect Repository Modal (unchanged)
// ---------------------------------------------------------------------------
function ConnectRepoModal({ isOpen, onClose, onConnect }) {
  const [tab, setTab] = useState('manual');
  const [platform, setPlatform] = useState('github');
  const [projectName, setProjectName] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [isPrivate, setIsPrivate] = useState(false);
  const [token, setToken] = useState('');
  const [showToken, setShowToken] = useState(false);
  const [autoScan, setAutoScan] = useState(true);
  const [scanFrequency, setScanFrequency] = useState('daily');
  const [connecting, setConnecting] = useState(false);

  async function handleConnect() {
    if (!projectName.trim() || !repoUrl.trim()) {
      alert('Please fill in the project name and repository URL');
      return;
    }
    if (isPrivate && !token.trim()) {
      alert('This is marked as a private repository — please provide an access token');
      return;
    }

    setConnecting(true);
    try {
      // Validate repo exists before creating project
      if (platform === 'github') {
        const validateRes = await fetch(`${API_URL}/validate-repo`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: repoUrl, token: token.trim() || undefined }),
        });
        const validateData = await validateRes.json();
        if (!validateData.valid) {
          alert(validateData.error || 'Repository not found. Check the URL and try again.');
          setConnecting(false);
          return;
        }
      }

      const payload = {
        name: projectName,
        platform: platform === 'github' ? 'GitHub' : 'GitLab',
        repos: [{ name: projectName, url: repoUrl, branch }],
        settings: { autoScan, scanFrequency },
        ...(token.trim() ? { token: token.trim() } : {}),
      };

      await onConnect(payload);
      setProjectName('');
      setRepoUrl('');
      setToken('');
      setIsPrivate(false);
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
          {/* Tab selector */}
          <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
            {[
              { key: 'manual', label: 'Manual Connect' },
              { key: 'github', label: 'Browse GitHub' },
            ].map((t) => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                style={{
                  padding: '6px 14px',
                  borderRadius: '6px',
                  fontSize: '13px',
                  fontWeight: 600,
                  cursor: 'pointer',
                  color: tab === t.key ? '#e8e9ee' : 'var(--text-faint)',
                  background: tab === t.key ? 'rgba(169,140,240,0.18)' : 'transparent',
                  border: tab === t.key ? '1px solid rgba(169,140,240,0.4)' : '1px solid transparent',
                }}
              >
                {t.label}
              </button>
            ))}
          </div>

          {/* GitHub Browse Tab */}
          {tab === 'github' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <GitHubLogin />
              <GitHubRepoBrowser
                onSelectRepo={async (repoInfo) => {
                  try {
                    if (!authUserId) {
                      alert('Please login with GitHub first');
                      return;
                    }
                    const res = await fetch(`${API_URL}/projects/from-github`, {
                      method: 'POST',
                      headers: {
                        'Content-Type': 'application/json',
                        'x-user-id': authUserId,
                      },
                      credentials: 'include',
                      body: JSON.stringify({
                        owner: repoInfo.owner,
                        repo: repoInfo.repo,
                        branch: repoInfo.branch,
                        name: repoInfo.name,
                      }),
                    });
                    if (!res.ok) {
                      const err = await res.json().catch(() => ({}));
                      throw new Error(err.error || 'Failed to connect repository');
                    }
                    const data = await res.json();
                    await onConnect({ _fromGithub: true, projectId: data.project?.id });
                    onClose();
                  } catch (err) {
                    alert('Failed to connect GitHub repository: ' + err.message);
                  }
                }}
              />
            </div>
          )}

          {/* Manual Connect Tab */}
          {tab === 'manual' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
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

          {/* Private repository toggle */}
          <div>
            <label style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}>
              <input
                type="checkbox"
                checked={isPrivate}
                onChange={(e) => setIsPrivate(e.target.checked)}
                style={{ width: '16px', height: '16px', accentColor: '#7c6ee8' }}
              />
              <span style={{ fontSize: '13px', fontWeight: 500 }}>This is a private repository</span>
            </label>
            <p style={{ fontSize: '11px', color: 'var(--text-faint)', marginTop: '6px' }}>
              Public repositories connect and scan automatically — no token needed. Only private repos require an access token.
            </p>
          </div>

          {/* Token — only required (and shown) for private repos */}
          {isPrivate && (
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
                Needs read access to the repo. Create a PAT at{' '}
                <a href={platform === 'github' ? 'https://github.com/settings/tokens' : 'https://gitlab.com/-/user_settings/personal_access_tokens'} target="_blank" rel="noreferrer" style={{ color: '#7ec3f5' }}>
                  {platform === 'github' ? 'github.com/settings/tokens' : 'gitlab.com/user_settings/personal_access_tokens'}
                </a>
              </p>
            </div>
          )}

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
        )}
        </div>
      </div>
    </div>
  );
}
// ---------------------------------------------------------------------------
function ProjectCard({ project, onSelect, onRescan, onDelete, onDownloadFixed, isScanning }) {
  const score = project.securityScore ?? 0;
  const scoreColor = score >= 80 ? '#4fd08a' : score >= 60 ? '#e8a33d' : '#e2504a';

  return (
    <div
      className="finding-card"
      style={{ cursor: isScanning ? 'default' : 'pointer', position: 'relative', opacity: isScanning ? 0.85 : 1 }}
      onClick={() => { if (!isScanning) onSelect(project); }}
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
            {isScanning ? <Loader2 size={16} className="spin" /> : <Folder size={16} />}
          </div>
          <div>
            <div style={{ fontWeight: 600, fontSize: '13.5px' }}>{project.name}</div>
            <div style={{ fontSize: '11px', color: 'var(--text-faint)', marginTop: '2px' }}>
              {project.platform} · {project.repos[0]?.branch || 'main'}
            </div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
          {isScanning ? (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '12px', fontWeight: 600, color: '#a98cf0', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Loader2 size={12} className="spin" /> Scanning…
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-faint)' }}>Analyzing code</div>
            </div>
          ) : (
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '18px', fontWeight: 700, color: scoreColor }}>
                {score}
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-faint)' }}>Score</div>
            </div>
          )}
        </div>
      </div>

      {/* Issues summary — only show when not scanning */}
      {!isScanning && (
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
          {project.medium > 0 && (
            <div className="summary-chip sev-medium" style={{ flex: 0 }}>
              {project.medium} medium
            </div>
          )}
          {project.low > 0 && (
            <div className="summary-chip sev-low" style={{ flex: 0 }}>
              {project.low} low
            </div>
          )}
          {project.critical === 0 && project.high === 0 && project.medium === 0 && project.low === 0 && (
            <div className="summary-chip" style={{ color: '#4fd08a', background: 'rgba(79,208,138,0.12)', border: '1px solid rgba(79,208,138,0.25)', flex: 0 }}>
              <CheckCircle2 size={11} /> No issues
            </div>
          )}
        </div>
      )}

      {/* Remediation progress — only show when not scanning */}
      {!isScanning && (
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
      )}

      {/* Last scan / Actions */}
      <div style={{ marginTop: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', color: 'var(--text-faint)' }}>
        <span>{isScanning ? 'Scan in progress…' : `Last scanned: ${formatDate(project.lastScan)}`}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
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
          <button
            className="text-btn"
            onClick={(e) => {
              e.stopPropagation();
              onDownloadFixed?.(project);
            }}
            disabled={isScanning}
            title="Download corrected repository as ZIP"
            style={{ padding: '4px 8px', fontSize: '11px', opacity: isScanning ? 0.6 : 1, cursor: isScanning ? 'default' : 'pointer' }}
          >
            <Download size={12} /> Fixed
          </button>
          <button
            className="text-btn"
            onClick={(e) => {
              e.stopPropagation();
              if (window.confirm(`Delete "${project.name}" from SecureCode? This will NOT affect the actual GitHub repository.`)) {
                onDelete?.(project);
              }
            }}
            disabled={isScanning}
            title="Delete repository from SecureCode"
            style={{ padding: '4px 8px', fontSize: '11px', color: '#e2504a', opacity: isScanning ? 0.6 : 1, cursor: isScanning ? 'default' : 'pointer' }}
          >
            <Trash2 size={12} />
          </button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Summary card (Security Score / Severity / Remediation / Total Issues)
// ---------------------------------------------------------------------------
function SummaryCard({ title, icon, children }) {
  return (
    <div className="dash-sub-panel" style={{ display: 'flex', flexDirection: 'column' }}>
      <h3 style={{ display: 'flex', alignItems: 'center', gap: '7px' }}>{icon}{title}</h3>
      <div style={{ marginTop: '6px', flex: 1 }}>{children}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Recursive file-tree node with per-file / per-folder vulnerability badges
// ---------------------------------------------------------------------------
function TreeNode({ node, depth, expanded, onToggle, selectedFile, onSelectFile, agg, scannedSet }) {
  const isDir = node.type === 'dir';
  const count = agg.count.get(node.path) || 0;
  const rank = agg.topRank.get(node.path);
  const badgeColor = rank != null ? Object.keys(SEV_ORDER).find((k) => SEV_ORDER[k] === rank) : null;
  const meta = badgeColor ? SEV_META[badgeColor] : null;
  const isOpen = expanded.has(node.path);
  const isSelected = !isDir && selectedFile === node.path;
  const wasScanned = scannedSet.has(node.path);

  return (
    <div>
      <div
        onClick={() => (isDir ? onToggle(node.path) : onSelectFile(isSelected ? null : node.path))}
        title={node.path}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          padding: '4px 8px',
          paddingLeft: `${8 + depth * 14}px`,
          borderRadius: '6px',
          cursor: 'pointer',
          background: isSelected ? 'rgba(169,140,240,0.14)' : 'transparent',
          border: isSelected ? '1px solid rgba(169,140,240,0.4)' : '1px solid transparent',
          fontSize: '12.5px',
          color: isDir ? 'var(--text)' : wasScanned ? 'var(--text)' : 'var(--text-faint)',
        }}
        onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = 'var(--panel)'; }}
        onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = 'transparent'; }}
      >
        {isDir ? (
          <>
            {isOpen ? <ChevronDown size={13} style={{ flexShrink: 0, opacity: 0.7 }} /> : <ChevronRight size={13} style={{ flexShrink: 0, opacity: 0.7 }} />}
            {isOpen ? <FolderOpen size={14} style={{ flexShrink: 0, color: '#e8a33d' }} /> : <Folder size={14} style={{ flexShrink: 0, color: '#e8a33d' }} />}
          </>
        ) : (
          <>
            <span style={{ width: 13, flexShrink: 0 }} />
            <FileCode2 size={14} style={{ flexShrink: 0, color: wasScanned ? '#3ba7f0' : 'var(--text-faint)' }} />
          </>
        )}
        <span style={{ flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{node.name}</span>
        {count > 0 && meta && (
          <span
            style={{
              flexShrink: 0,
              fontSize: '10.5px',
              fontWeight: 700,
              minWidth: '18px',
              textAlign: 'center',
              padding: '1px 6px',
              borderRadius: '999px',
              color: meta.color,
              background: meta.bg,
              border: `1px solid ${meta.border}`,
            }}
            title={`${count} ${count === 1 ? 'issue' : 'issues'}`}
          >
            {count}
          </span>
        )}
      </div>

      {isDir && isOpen && sortedChildren(node).map((child) => (
        <TreeNode
          key={child.path}
          node={child}
          depth={depth + 1}
          expanded={expanded}
          onToggle={onToggle}
          selectedFile={selectedFile}
          onSelectFile={onSelectFile}
          agg={agg}
          scannedSet={scannedSet}
        />
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Vulnerable / secure code panes with exact red/green line highlighting
// ---------------------------------------------------------------------------
function CodePane({ title, marks, startLine, theme }) {
  const strong = theme === 'red' ? 'rgba(255,60,95,0.16)' : 'rgba(79,208,138,0.16)';
  const border = theme === 'red' ? '#ff3c5f' : '#4fd08a';
  const head = theme === 'red' ? '#ff8792' : '#7fe0ac';
  return (
    <div style={{ border: '1px solid var(--border)', borderRadius: '8px', overflow: 'hidden', background: 'var(--panel)' }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: '6px', padding: '6px 10px',
        borderBottom: '1px solid var(--border)', background: 'var(--panel-2)',
        fontSize: '11px', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase', color: head,
      }}>
        {theme === 'red' ? <AlertTriangle size={12} /> : <CheckCircle2 size={12} />}
        {title}
      </div>
      <div style={{ overflowX: 'auto', fontFamily: "'JetBrains Mono', monospace", fontSize: '12.3px', lineHeight: '1.55' }}>
        {marks.map((m, i) => (
          <div
            key={i}
            style={{
              display: 'flex',
              background: m.changed ? strong : 'transparent',
              borderLeft: m.changed ? `3px solid ${border}` : '3px solid transparent',
            }}
          >
            <span style={{
              flexShrink: 0, width: '42px', textAlign: 'right', paddingRight: '10px',
              color: 'var(--text-faint)', userSelect: 'none', opacity: 0.7,
            }}>
              {startLine + i}
            </span>
            <span style={{
              whiteSpace: 'pre', paddingRight: '12px',
              color: m.changed ? 'var(--text)' : 'var(--text-faint)',
              flex: 1,
            }}>
              {m.text === '' ? ' ' : m.text}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function VulnDetail({ finding }) {
  const meta = sevMeta(finding.severity);
  const startLine = codeStartLine(finding);
  const { vulnMarks, corrMarks } = diffLines(finding.vulnerableCode, finding.correctedCode);
  const hasFix = (finding.correctedCode || '').trim() && (finding.correctedCode || '').trim() !== (finding.vulnerableCode || '').trim();

  const Field = ({ label, children }) => (
    <div style={{ marginBottom: '10px' }}>
      <div style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '0.04em', textTransform: 'uppercase', color: 'var(--text-faint)', marginBottom: '3px' }}>{label}</div>
      <div style={{ fontSize: '13px', lineHeight: 1.5 }}>{children}</div>
    </div>
  );

  return (
    <div style={{ padding: '14px', borderTop: '1px solid var(--border)', background: 'var(--panel)' }}>
      <Field label="Description">{finding.explanation || '—'}</Field>
      <Field label="Impact">{finding.impact || '—'}</Field>
      <Field label="Recommendation">{finding.fix || '—'}</Field>

      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', margin: '12px 0' }}>
        {finding.cwe && (
          <span className="chip" style={{ fontSize: '11px' }}>{finding.cwe}</span>
        )}
        {finding.owasp && (
          <span className="chip" style={{ fontSize: '11px' }}>{finding.owasp}</span>
        )}
        {finding.packageName && (
          <span className="chip" style={{ fontSize: '11px' }}>
            {finding.packageName}@{finding.version}{finding.fixedVersion ? ` → ${finding.fixedVersion}` : ''}
          </span>
        )}
        {finding.osvUrl && (
          <a href={finding.osvUrl} target="_blank" rel="noreferrer" className="chip" style={{ fontSize: '11px', color: '#7ec3f5', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
            OSV advisory <ExternalLink size={11} />
          </a>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
        <CodePane title="Vulnerable Code" marks={vulnMarks} startLine={startLine} theme="red" />
        {hasFix
          ? <CodePane title="Secure Fix" marks={corrMarks} startLine={startLine} theme="green" />
          : (
            <div style={{ border: '1px solid var(--border)', borderRadius: '8px', padding: '12px', background: 'var(--panel)', fontSize: '12.5px', color: 'var(--text-faint)', display: 'flex', alignItems: 'center' }}>
              No automated code fix available — follow the recommendation above.
            </div>
          )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Repository Details View — real file tree, real counts, real findings
// ---------------------------------------------------------------------------
const PAGE_SIZE = 8;

function RepoDetailView({ project, onBack, onAutoScanToggle, onProjectsChanged, onDeleteProject, onRescan: parentRescan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [rescanning, setRescanning] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [autoScan, setAutoScan] = useState(project.autoScanEnabled);
  const [detailTab, setDetailTab] = useState('scan-results');
  const [authUserId, setAuthUserId] = useState(null);

  // Check GitHub session on mount
  useEffect(() => {
    fetch(`${API_URL}/auth/github/session`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.authenticated && data.user) {
          setAuthUserId(String(data.user.id));
        } else {
          setAuthUserId(null);
        }
      })
      .catch(() => setAuthUserId(null));
  }, []);

  const [selectedFile, setSelectedFile] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [openKey, setOpenKey] = useState(null);
  const [expanded, setExpanded] = useState(new Set());

  const pollRef = useRef(null);
  const initExpandedRef = useRef(false);
  const [rescanCorrecting, setRescanCorrecting] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [pushResult, setPushResult] = useState(null);
  const [showPRModal, setShowPRModal] = useState(false);

  async function loadScans() {
    try {
      const res = await fetch(`${API_URL}/projects/${project.id}/scans`);
      const data = await res.json();
      return data.scans || [];
    } catch (err) {
      console.error('Failed to load scan history:', err);
      return [];
    }
  }

  function startPolling() {
    if (pollRef.current) return;
    setRescanning(true);
    pollRef.current = setInterval(async () => {
      const list = await loadScans();
      setScans(list);
      const latest = list[0];
      if (latest && latest.status !== 'in_progress') {
        clearInterval(pollRef.current);
        pollRef.current = null;
        setRescanning(false);
        onProjectsChanged?.();
      }
    }, 3000);
  }

  useEffect(() => {
    let cancelled = false;
    (async () => {
      setLoading(true);
      const list = await loadScans();
      if (cancelled) return;
      setScans(list);
      setLoading(false);
      // If a scan (e.g. the automatic first scan) is still running, keep polling.
      if (list[0] && list[0].status === 'in_progress') startPolling();
    })();
    return () => {
      cancelled = true;
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [project.id]);

  const completedScans = useMemo(() => scans.filter((s) => s.status === 'completed'), [scans]);
  const latest = completedScans[0] || null;
  const findings = useMemo(() => (Array.isArray(latest?.findings) ? latest.findings : []), [latest]);

  // Real aggregate numbers — prefer the counts the backend stored, fall back to
  // recomputing from the findings array so the view is always self-consistent.
  const counts = useMemo(() => {
    const c = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    for (const f of findings) c[normSev(f.severity)] += 1;
    return c;
  }, [findings]);

  const securityScore = latest?.securityScore != null ? latest.securityScore : project.securityScore ?? 0;
  const totalIssues = latest?.total != null ? latest.total : findings.length;
  const affectedFiles = useMemo(() => new Set(findings.map((f) => f.fileName).filter(Boolean)).size, [findings]);

  const scoreLabel = securityScore >= 85 ? 'Excellent' : securityScore >= 70 ? 'Good' : securityScore >= 50 ? 'Fair' : 'Poor';
  const scoreColor = securityScore >= 85 ? '#4fd08a' : securityScore >= 70 ? '#8fd04f' : securityScore >= 50 ? '#e8a33d' : '#e2504a';

  // Remediation: baseline = worst-ever total across completed scans.
  const baseline = useMemo(() => {
    const totals = completedScans.map((s) => (s.total != null ? s.total : (s.findings?.length || 0)));
    return totals.length ? Math.max(...totals) : totalIssues;
  }, [completedScans, totalIssues]);
  const remaining = totalIssues;
  const fixed = Math.max(0, baseline - remaining);
  const remediationProgress = baseline > 0 ? Math.round((fixed / baseline) * 100) : (remaining === 0 ? 100 : 0);

  const agg = useMemo(() => computeTreeAggregates(findings), [findings]);
  const tree = useMemo(() => buildFileTree(latest?.fileTree || []), [latest]);
  const scannedSet = useMemo(() => new Set(latest?.scannedFiles || []), [latest]);

  // Auto-expand folders that contain a finding, the first time data arrives.
  useEffect(() => {
    if (initExpandedRef.current || findings.length === 0) return;
    const next = new Set();
    for (const f of findings) {
      if (!f.fileName) continue;
      const parts = f.fileName.split('/');
      let acc = '';
      for (let i = 0; i < parts.length - 1; i++) { acc = acc ? `${acc}/${parts[i]}` : parts[i]; next.add(acc); }
    }
    setExpanded(next);
    initExpandedRef.current = true;
  }, [findings]);

  function toggleFolder(path) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path); else next.add(path);
      return next;
    });
  }

  // Filtered issue list (severity tab + selected file + text search).
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings
      .map((f, idx) => ({ f, idx }))
      .filter(({ f }) => {
        if (severityFilter !== 'all' && normSev(f.severity) !== severityFilter) return false;
        if (selectedFile && f.fileName !== selectedFile) return false;
        if (q) {
          const hay = `${f.type} ${f.fileName} ${f.cwe} ${f.owasp} ${f.explanation}`.toLowerCase();
          if (!hay.includes(q)) return false;
        }
        return true;
      })
      .sort((a, b) => (SEV_ORDER[normSev(a.f.severity)] - SEV_ORDER[normSev(b.f.severity)]) || ((a.f.line || 0) - (b.f.line || 0)));
  }, [findings, severityFilter, selectedFile, search]);

  useEffect(() => { setPage(0); setOpenKey(null); }, [severityFilter, selectedFile, search]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageItems = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);

  async function handleRescan() {
    if (rescanning) return;
    if (parentRescan) {
      parentRescan(project);
      setRescanning(true);
      initExpandedRef.current = false;
      startPolling();
      return;
    }
    try {
      const res = await fetch(`${API_URL}/projects/${project.id}/scan`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to start scan');
      }
      initExpandedRef.current = false;
      startPolling();
    } catch (err) {
      alert('Failed to start scan: ' + err.message);
    }
  }

  async function handleRescanCorrected() {
    if (rescanCorrecting) return;
    setRescanCorrecting(true);
    try {
      const res = await fetch(`${API_URL}/projects/${project.id}/rescan-corrected`, { method: 'POST' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to start re-scan');
      }
      initExpandedRef.current = false;
      startPolling();
    } catch (err) {
      alert('Re-scan corrected failed: ' + err.message);
    } finally {
      setRescanCorrecting(false);
    }
  }

  async function handlePushToGitHub() {
    if (pushing) return;
    if (!latest?.filesCorrected || Object.keys(latest.filesCorrected).length === 0) {
      alert('No corrected code available. Generate fixes first.');
      return;
    }

    if (!authUserId) {
      alert('GitHub not connected. Please log in with GitHub first.');
      return;
    }

    const branchName = prompt('Branch name for fixes:', 'securecode/security-fixes');
    if (!branchName) return;

    setPushing(true);
    setPushResult(null);
    try {
      const files = Object.entries(latest.filesCorrected).map(([path, content]) => ({ path, content: String(content || '') }));

      // Resolve owner/repo: prefer direct fields, fall back to parsing the repo URL
      let owner = project.githubOwner || project.github_owner;
      let repo = project.githubRepo || project.github_repo;
      if (!owner || !repo) {
        const rawUrl = project.repos?.[0]?.url || project.githubUrl || project.github_url || '';
        const m = rawUrl.match(/github\.com[/:]([^/]+)\/([^/.]+)/i);
        if (m) { owner = m[1]; repo = m[2]; }
      }
      if (!owner || !repo) {
        throw new Error('Could not identify GitHub owner/repo. Make sure the repository URL is set.');
      }

      const res = await fetch(`${API_URL}/github/push`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-user-id': authUserId,
        },
        credentials: 'include',
        body: JSON.stringify({
          owner, repo,
          baseBranch: project.repos?.[0]?.branch || 'main',
          branchName,
          files,
          message: 'fix: security remediation by SecureCode',
        }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        if (res.status === 401) {
          throw new Error('GitHub authentication required. Please connect your GitHub account in Settings.');
        }
        throw new Error(err.details || err.error || `HTTP ${res.status}`);
      }
      const data = await res.json();
      setPushResult(data);
    } catch (err) {
      alert('Push failed: ' + err.message);
    } finally {
      setPushing(false);
    }
  }

  async function handleDelete() {
    if (!window.confirm(`Delete "${project.name}" from SecureCode? This will NOT affect the actual GitHub repository.`)) return;
    setDeleting(true);
    try {
      await onDeleteProject?.(project.id);
    } finally {
      setDeleting(false);
    }
  }

  async function handleAutoScanToggle() {
    const next = !autoScan;
    setAutoScan(next);
    onAutoScanToggle(project.id, next);
  }

  // Download a real, self-contained HTML report built from this scan's data.
  function downloadReport() {
    if (!latest) return;
    const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const rows = findings.map((f) => `
      <tr>
        <td><span class="sev ${normSev(f.severity).toLowerCase()}">${normSev(f.severity)}</span></td>
        <td>${esc(f.type)}</td>
        <td class="mono">${esc(f.fileName || '')}:${esc(f.line || '')}</td>
        <td>${esc(f.cwe || '')}</td>
        <td>${esc(f.fix || '')}</td>
      </tr>`).join('');
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>SecureCode Report — ${esc(project.name)}</title>
      <style>
        body{font-family:system-ui,sans-serif;background:#0a0c12;color:#e8e9ee;margin:0;padding:32px}
        h1{margin:0 0 4px} .muted{color:#8a8f9c;font-size:13px}
        .cards{display:flex;gap:16px;margin:22px 0}
        .card{background:#12141c;border:1px solid #232633;border-radius:10px;padding:16px 20px;min-width:120px}
        .card .big{font-size:26px;font-weight:800}
        table{width:100%;border-collapse:collapse;margin-top:12px;font-size:13px}
        th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #232633;vertical-align:top}
        th{color:#8a8f9c;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
        .mono{font-family:ui-monospace,monospace;font-size:12px;color:#9fb6d6}
        .sev{padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
        .sev.critical{background:rgba(255,60,95,.15);color:#ff3c5f}
        .sev.high{background:rgba(232,163,61,.15);color:#e8a33d}
        .sev.medium{background:rgba(217,201,79,.15);color:#d9c94f}
        .sev.low{background:rgba(79,208,138,.15);color:#4fd08a}
        .sev.info{background:rgba(138,143,156,.15);color:#8a8f9c}
      </style></head><body>
      <h1>${esc(project.name)}</h1>
      <div class="muted">${esc(project.platform)} · ${esc(project.repos?.[0]?.url || '')} · Scanned ${esc(formatDate(latest.scannedAt))}</div>
      <div class="cards">
        <div class="card"><div class="muted">Security Score</div><div class="big" style="color:${scoreColor}">${securityScore}/100</div></div>
        <div class="card"><div class="muted">Total Issues</div><div class="big">${totalIssues}</div></div>
        <div class="card"><div class="muted">Critical / High</div><div class="big">${counts.Critical} / ${counts.High}</div></div>
        <div class="card"><div class="muted">Remediation</div><div class="big">${remediationProgress}%</div></div>
      </div>
      <table><thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>CWE</th><th>Recommendation</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5" class="muted">No issues found.</td></tr>'}</tbody></table>
      </body></html>`;
    const blob = new Blob([html], { type: 'text/html' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `securecode-report-${project.name}-${new Date().toISOString().slice(0, 10)}.html`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(a.href);
  }

  const repoUrl = project.repos?.[0]?.url || '';
  const branch = project.repos?.[0]?.branch || 'main';
  const severityTabs = ['all', 'Critical', 'High', 'Medium', 'Low', 'Info']
    .filter((t) => t === 'all' || counts[t] > 0);

  const noCompletedScan = !latest;

  // When per-file data is available, use the unified FolderScanResults view
  const hasPerFileData = latest?.filesOriginal && latest?.filesCorrected && latest?.findingsByFile;

  // Show scanning/failed banners before the per-file data check
  if (loading) {
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', marginBottom: '18px' }}>
          <button className="icon-btn" onClick={onBack} aria-label="Back to projects"><ArrowLeft size={16} /></button>
          <div style={{ flex: 1 }}>
            <h2 style={{ margin: 0, fontSize: '19px', display: 'flex', alignItems: 'center', gap: '9px' }}>
              <Folder size={18} style={{ color: '#3ba7f0' }} /> {project.name}
            </h2>
          </div>
        </div>
        <p className="empty-sub">Loading repository analysis…</p>
      </div>
    );
  }

  if (rescanning || (scans[0] && scans[0].status === 'in_progress')) {
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', marginBottom: '18px' }}>
          <button className="icon-btn" onClick={onBack} aria-label="Back to projects"><ArrowLeft size={16} /></button>
          <div style={{ flex: 1 }}>
            <h2 style={{ margin: 0, fontSize: '19px', display: 'flex', alignItems: 'center', gap: '9px' }}>
              <Folder size={18} style={{ color: '#3ba7f0' }} /> {project.name}
            </h2>
          </div>
        </div>
        <div className="finding-card" style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '10px', color: '#a98cf0' }}>
          <Loader2 size={16} className="spin" /> Scan in progress — results update automatically when it finishes.
        </div>
      </div>
    );
  }

  if (noCompletedScan) {
    const hasFailedScan = scans.some((s) => s.status === 'failed');
    const failedScan = scans.find((s) => s.status === 'failed');
    return (
      <div>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', marginBottom: '18px' }}>
          <button className="icon-btn" onClick={onBack} aria-label="Back to projects"><ArrowLeft size={16} /></button>
          <div style={{ flex: 1 }}>
            <h2 style={{ margin: 0, fontSize: '19px', display: 'flex', alignItems: 'center', gap: '9px' }}>
              <Folder size={18} style={{ color: '#3ba7f0' }} /> {project.name}
            </h2>
          </div>
          <button className="scan-btn" style={{ padding: '8px 14px' }} onClick={handleRescan}>
            <RefreshCw size={14} /> Rescan
          </button>
        </div>
        <div className="finding-card" style={{ marginBottom: '16px', display: 'flex', alignItems: 'flex-start', gap: '10px', color: hasFailedScan ? '#e2504a' : '#e8a33d' }}>
          <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <div style={{ fontWeight: 600, marginBottom: '4px' }}>
              {hasFailedScan ? 'Scan failed' : 'No completed scan yet'}
            </div>
            {hasFailedScan && failedScan?.errorMessage && (
              <div style={{ fontSize: '12px', opacity: 0.9, lineHeight: 1.4 }}>{failedScan.errorMessage}</div>
            )}
            {hasFailedScan && !failedScan?.errorMessage && (
              <div style={{ fontSize: '12px', opacity: 0.8 }}>Repo unreachable, private without a valid token, or no scannable files. Try Rescan.</div>
            )}
            {!hasFailedScan && (
              <div style={{ fontSize: '12px', opacity: 0.8 }}>Run a scan to populate results.</div>
            )}
          </div>
        </div>
      </div>
    );
  }

  if (hasPerFileData) {
    return (
      <FolderScanResults
        scanData={latest}
        project={project}
        onBack={onBack}
        onRescan={handleRescan}
        onDelete={(id) => onDeleteProject?.(id)}
      />
    );
  }

  return (
    <>
      {/* ---------------- Header ---------------- */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', marginBottom: '18px', flexWrap: 'wrap' }}>
        <button className="icon-btn" onClick={onBack} aria-label="Back to projects">
          <ArrowLeft size={16} />
        </button>
        <div style={{ flex: 1, minWidth: '220px' }}>
          <h2 style={{ margin: '0 0 6px', fontSize: '19px', display: 'flex', alignItems: 'center', gap: '9px' }}>
            <Folder size={18} style={{ color: '#3ba7f0' }} /> {project.name}
          </h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', fontSize: '12px', color: 'var(--text-faint)' }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              {project.isPrivate ? <Lock size={12} /> : <Globe size={12} />}{project.isPrivate ? 'Private' : 'Public'}
            </span>
            <span>·</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}><GitBranch size={12} /> {project.platform}</span>
            <span>·</span>
            <span>{branch}</span>
            <span>·</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}><Clock size={12} /> Last scanned: {formatDate(latest?.scannedAt || project.lastScan)}</span>
            {repoUrl && (
              <a href={repoUrl.startsWith('http') ? repoUrl : `https://${repoUrl}`} target="_blank" rel="noreferrer" style={{ color: '#7ec3f5', display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
                <ExternalLink size={12} /> Open repo
              </a>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', position: 'relative' }}>
          <button className="scan-btn" style={{ padding: '8px 14px' }} onClick={handleRescan} disabled={rescanning}>
            {rescanning ? <><Loader2 size={14} className="spin" /> Scanning…</> : <><RefreshCw size={14} /> Rescan</>}
          </button>
          {latest?.filesCorrected && Object.keys(latest.filesCorrected).length > 0 && (() => {
            return (
              <>
                <button className="ghost-btn" style={{ padding: '8px 14px', fontSize: '12px' }} onClick={handleRescanCorrected} disabled={rescanCorrecting || rescanning}>
                  {rescanCorrecting ? <><Loader2 size={13} className="spin" /> Re-scanning…</> : <><RefreshCw size={13} /> Re-scan Corrected</>}
                </button>
                <button className="ghost-btn" style={{ padding: '8px 14px', fontSize: '12px', color: '#7ec3f5' }} onClick={handlePushToGitHub} disabled={pushing}>
                  {pushing ? <><Loader2 size={13} className="spin" /> Pushing…</> : <><ExternalLink size={13} /> Push to GitHub</>}
                </button>
                <button className="ghost-btn" style={{ padding: '8px 14px', fontSize: '12px', color: '#a78bfa' }} onClick={() => setShowPRModal(true)}>
                  <GitBranch size={13} /> Create PR
                </button>
              </>
            );
          })()}
          {pushResult && (
            <div style={{ position: 'absolute', top: '100%', right: 0, marginTop: '8px', padding: '10px 14px', background: 'var(--panel)', border: '1px solid rgba(79,208,138,0.4)', borderRadius: '8px', fontSize: '12px', zIndex: 10, minWidth: '250px' }}>
              <div style={{ color: '#4fd08a', fontWeight: 600, marginBottom: '4px' }}>Push successful!</div>
              <div>Branch: <span style={{ fontFamily: 'monospace' }}>{pushResult.branch}</span></div>
              <div>SHA: <span style={{ fontFamily: 'monospace', fontSize: '11px' }}>{pushResult.commitSha?.slice(0, 8)}</span></div>
              {pushResult.url && <a href={pushResult.url} target="_blank" rel="noreferrer" style={{ color: '#7ec3f5', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '4px' }}><ExternalLink size={11} /> View on GitHub</a>}
              <button className="text-btn" style={{ marginTop: '6px', fontSize: '11px' }} onClick={() => setPushResult(null)}>Dismiss</button>
            </div>
          )}
          <button className="ghost-btn" onClick={downloadReport} disabled={!latest} style={{ opacity: latest ? 1 : 0.5 }}>
            <Download size={14} /> Download Report
          </button>
          <button className="icon-btn" onClick={() => setShowSettings((v) => !v)} aria-label="Settings">
            <Settings size={16} />
          </button>
          <button className="icon-btn" onClick={handleDelete} disabled={deleting} title="Delete repository" style={{ color: '#e2504a' }}>
            {deleting ? <Loader2 size={15} className="spin" /> : <Trash2 size={15} />}
          </button>

          {showSettings && (
            <div className="panel" style={{ position: 'absolute', top: '46px', right: 0, zIndex: 20, width: '260px', padding: '14px' }}>
              <div className="settings-row" style={{ borderBottom: 'none', margin: 0, padding: 0 }}>
                <div>
                  <div className="settings-label">Automatic Scanning</div>
                  <div className="settings-sub" style={{ maxWidth: '160px' }}>Scan on schedule</div>
                </div>
                <button className={`toggle ${autoScan ? 'on' : ''}`} onClick={handleAutoScanToggle} aria-label="Toggle auto-scan">
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
                    onChange={(e) => onAutoScanToggle(project.id, autoScan, e.target.value)}
                  >
                    <option value="on-push">On every push</option>
                    <option value="daily">Daily</option>
                    <option value="weekly">Weekly</option>
                  </select>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', borderBottom: '1px solid var(--border)', paddingBottom: '8px' }}>
        <button
          onClick={() => setDetailTab('scan-results')}
          style={{
            padding: '8px 16px',
            background: detailTab === 'scan-results' ? '#007bff' : 'transparent',
            border: 'none',
            color: detailTab === 'scan-results' ? '#fff' : '#999',
            cursor: 'pointer',
            borderRadius: '4px',
            fontSize: '13px',
            fontWeight: detailTab === 'scan-results' ? '600' : '400',
          }}
        >
          📊 Scan Results
        </button>
        <button
          onClick={() => setDetailTab('deployment')}
          style={{
            padding: '8px 16px',
            background: detailTab === 'deployment' ? '#007bff' : 'transparent',
            border: 'none',
            color: detailTab === 'deployment' ? '#fff' : '#999',
            cursor: 'pointer',
            borderRadius: '4px',
            fontSize: '13px',
            fontWeight: detailTab === 'deployment' ? '600' : '400',
          }}
        >
          ☁️ Deployment
        </button>
      </div>

      {/* Deployment Tab */}
      {detailTab === 'deployment' && (
        <DeploymentDashboard
          projectId={project.id}
          projectName={project.name}
          repoUrl={project.repos?.[0]?.url || ''}
          branch={project.repos?.[0]?.branch || 'main'}
        />
      )}

      {/* Scan Results Tab */}
      {detailTab === 'scan-results' && (
      <>

      {/* -------------------- Summary cards -------------------- */}
          <div className="dash-mid-grid" style={{ marginBottom: '16px' }}>
            <SummaryCard title="Security Score" icon={<Shield size={15} />}>
              <div className="dash-donut-row">
                <svg width="96" height="96" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="5" />
                  <circle
                    cx="21" cy="21" r="15.9" fill="transparent"
                    stroke={scoreColor} strokeWidth="5" strokeLinecap="round"
                    strokeDasharray={`${securityScore} ${100 - securityScore}`}
                    strokeDashoffset="25"
                  />
                  <text x="21" y="20" textAnchor="middle" fontSize="9" fill="#e8e9ee" fontWeight="700">{securityScore}</text>
                  <text x="21" y="27" textAnchor="middle" fontSize="3.6" fill="#5c5f6d">/ 100</text>
                </svg>
                <div className="dash-stat-sub" style={{ color: scoreColor, fontWeight: 700, fontSize: '14px' }}>{scoreLabel}</div>
              </div>
            </SummaryCard>

            <SummaryCard title="Severity Breakdown" icon={<AlertTriangle size={15} />}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '7px' }}>
                {['Critical', 'High', 'Medium', 'Low', 'Info'].map((s) => (
                  <div className="dash-cat-row" key={s}>
                    <span className="dash-dot" style={{ background: SEV_META[s].dot }} />
                    <div className="dash-cat-label">{s}</div>
                    <div className="dash-cat-count" style={{ color: counts[s] > 0 ? SEV_META[s].color : 'var(--text-faint)' }}>{counts[s]}</div>
                  </div>
                ))}
              </div>
            </SummaryCard>

            <SummaryCard title="Remediation Progress" icon={<CheckCircle2 size={15} />}>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '26px', fontWeight: 800, color: '#a98cf0' }}>{remediationProgress}%</span>
              </div>
              <div className="dash-cat-track" style={{ height: '8px' }}>
                <div className="dash-cat-fill" style={{ width: `${remediationProgress}%`, background: remediationProgress >= 80 ? '#4fd08a' : remediationProgress >= 50 ? '#e8a33d' : '#a98cf0' }} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11.5px', color: 'var(--text-faint)', marginTop: '8px' }}>
                <span style={{ color: '#4fd08a' }}>Fixed: {fixed}</span>
                <span style={{ color: '#e8a33d' }}>Remaining: {remaining}</span>
              </div>
            </SummaryCard>

            <SummaryCard title="Total Issues" icon={<Bug size={15} />}>
              <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', height: '100%' }}>
                <span style={{ fontSize: '34px', fontWeight: 800 }}>{totalIssues}</span>
                <span style={{ fontSize: '12px', color: 'var(--text-faint)' }}>Across {affectedFiles} {affectedFiles === 1 ? 'file' : 'files'}</span>
              </div>
            </SummaryCard>
          </div>

          {/* ---------------- Tree + Issues ---------------- */}
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 300px) 1fr', gap: '16px', alignItems: 'start' }}>
            {/* File tree */}
            <section className="panel" style={{ padding: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <h2 style={{ fontSize: '14px', margin: 0, display: 'flex', alignItems: 'center', gap: '7px' }}><FolderOpen size={15} /> Repository Files</h2>
                {selectedFile && (
                  <button className="text-btn" style={{ fontSize: '11px', padding: '3px 7px' }} onClick={() => setSelectedFile(null)}>
                    <X size={11} /> Clear
                  </button>
                )}
              </div>
              {(latest?.fileTree || []).length === 0 ? (
                <p className="empty-sub">No file tree captured for this scan.</p>
              ) : (
                <div style={{ maxHeight: '520px', overflowY: 'auto', margin: '0 -4px' }}>
                  {sortedChildren(tree).map((child) => (
                    <TreeNode
                      key={child.path}
                      node={child}
                      depth={0}
                      expanded={expanded}
                      onToggle={toggleFolder}
                      selectedFile={selectedFile}
                      onSelectFile={setSelectedFile}
                      agg={agg}
                      scannedSet={scannedSet}
                    />
                  ))}
                </div>
              )}
              {latest?.treeTruncated && (
                <p className="empty-sub" style={{ marginTop: '8px' }}>Large repo — tree truncated for display.</p>
              )}
            </section>

            {/* Issues */}
            <section className="panel" style={{ padding: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px', flexWrap: 'wrap', marginBottom: '12px' }}>
                <h2 style={{ fontSize: '14px', margin: 0, display: 'flex', alignItems: 'center', gap: '7px' }}>
                  <Bug size={15} /> Security Issues
                  {selectedFile && (
                    <span className="chip" style={{ fontSize: '11px', fontFamily: "'JetBrains Mono', monospace" }}>{selectedFile}</span>
                  )}
                </h2>
                <div style={{ position: 'relative' }}>
                  <Search size={13} style={{ position: 'absolute', left: '9px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-faint)' }} />
                  <input
                    className="code-input"
                    style={{ height: 'auto', padding: '6px 10px 6px 28px', width: '200px', fontSize: '12.5px' }}
                    placeholder="Search issues…"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
              </div>

              {/* Severity tabs */}
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '12px' }}>
                {severityTabs.map((t) => {
                  const active = severityFilter === t;
                  const m = t === 'all' ? null : SEV_META[t];
                  const label = t === 'all' ? `All (${findings.length})` : `${t} (${counts[t]})`;
                  return (
                    <button
                      key={t}
                      onClick={() => setSeverityFilter(t)}
                      style={{
                        padding: '5px 11px',
                        borderRadius: '999px',
                        fontSize: '12px',
                        fontWeight: 600,
                        cursor: 'pointer',
                        color: active ? (m ? m.color : '#e8e9ee') : 'var(--text-faint)',
                        background: active ? (m ? m.bg : 'var(--panel-2)') : 'transparent',
                        border: `1px solid ${active ? (m ? m.border : 'var(--border)') : 'var(--border)'}`,
                      }}
                    >
                      {label}
                    </button>
                  );
                })}
              </div>

              {/* Issue rows */}
              {filtered.length === 0 ? (
                <p className="empty-sub">
                  {findings.length === 0
                    ? 'No vulnerabilities detected in this scan. 🎉'
                    : selectedFile
                      ? 'No issues in the selected file for this filter.'
                      : 'No issues match the current filter.'}
                </p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {pageItems.map(({ f, idx }) => {
                    const key = findingKey(f, idx);
                    const m = sevMeta(f.severity);
                    const isOpen = openKey === key;
                    return (
                      <div key={key} className="finding-card" style={{ padding: 0, overflow: 'hidden', borderColor: isOpen ? m.border : 'var(--border)' }}>
                        <div
                          onClick={() => setOpenKey(isOpen ? null : key)}
                          style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '11px 12px', cursor: 'pointer' }}
                        >
                          <span style={{
                            flexShrink: 0, fontSize: '10.5px', fontWeight: 700, textTransform: 'uppercase',
                            letterSpacing: '0.03em', padding: '2px 8px', borderRadius: '999px',
                            color: m.color, background: m.bg, border: `1px solid ${m.border}`,
                          }}>
                            {normSev(f.severity)}
                          </span>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontWeight: 600, fontSize: '13px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.type}</div>
                            <div style={{ fontSize: '11.5px', color: 'var(--text-faint)', fontFamily: "'JetBrains Mono', monospace", overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {f.fileName || 'source'}:{f.line || '—'}
                            </div>
                          </div>
                          <span className="chip" style={{ fontSize: '10.5px', flexShrink: 0 }}>{f.category || 'Security'}</span>
                          {isOpen ? <ChevronDown size={15} style={{ flexShrink: 0, opacity: 0.6 }} /> : <ChevronRight size={15} style={{ flexShrink: 0, opacity: 0.6 }} />}
                        </div>
                        {isOpen && <VulnDetail finding={f} />}
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Pagination */}
              {pageCount > 1 && (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '12px', marginTop: '14px' }}>
                  <button className="icon-btn" style={{ width: '30px', height: '30px' }} disabled={page === 0} onClick={() => setPage((p) => Math.max(0, p - 1))}>
                    <ChevronLeft size={15} />
                  </button>
                  <span style={{ fontSize: '12px', color: 'var(--text-faint)' }}>Page {page + 1} of {pageCount}</span>
                  <button className="icon-btn" style={{ width: '30px', height: '30px' }} disabled={page >= pageCount - 1} onClick={() => setPage((p) => Math.min(pageCount - 1, p + 1))}>
                    <ChevronRight size={15} />
                  </button>
                </div>
              )}
            </section>
          </div>
      </>
      )}

      {/* PR Creation Modal */}
      <PRCreationModal
        isOpen={showPRModal}
        onClose={() => { setShowPRModal(false); onProjectsChanged?.(); }}
        project={project}
        findings={findings}
        filesOriginal={latest?.filesOriginal || {}}
        filesCorrected={latest?.filesCorrected || {}}
      />
    </>
  );
}

// ---------------------------------------------------------------------------
// Main Projects Panel
// ---------------------------------------------------------------------------
export default function ProjectsPanel({ onProjectSelect }) {
  const [projects, setProjects] = useState([]);
  const [selectedProject, setSelectedProject] = useState(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [ghConfirmOpen, setGhConfirmOpen] = useState(false);
  const [loading, setLoading] = useState(true);
  const [scanningIds, setScanningIds] = useState(new Set());
  const [authUserId, setAuthUserId] = useState(null);
  const pollRef = useRef(null);

  // Check GitHub session on mount
  useEffect(() => {
    fetch(`${API_URL}/auth/github/session`, { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.authenticated && data.user) {
          setAuthUserId(String(data.user.id));
        } else {
          setAuthUserId(null);
        }
      })
      .catch(() => setAuthUserId(null));
  }, []);

  // Notify parent when project selection changes
  useEffect(() => {
    onProjectSelect?.(selectedProject);
  }, [selectedProject]);

  // Clean up polling on unmount
  useEffect(() => {
    return () => {
      if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    };
  }, []);

  async function loadProjects() {
    try {
      const res = await fetch(`${API_URL}/projects`);
      const data = await res.json();
      setProjects(data.projects || []);
      // Keep the open detail view's header meta fresh after a rescan.
      setSelectedProject((prev) => (prev ? (data.projects || []).find((p) => p.id === prev.id) || prev : prev));
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
    if (payload._fromGithub) {
      await loadProjects();
      return;
    }
    const res = await fetch(`${API_URL}/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to connect repository');
    }
    const data = await res.json();
    await loadProjects();
  }

  async function handleAutoScanToggle(projectId, enabled, frequency) {
    try {
      const body = { autoScanEnabled: enabled };
      if (frequency) body.autoScanFrequency = frequency;
      await fetch(`${API_URL}/projects/${projectId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
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
      startPolling(project.id);
    } catch (err) {
      setScanningIds((prev) => {
        const next = new Set(prev);
        next.delete(project.id);
        return next;
      });
      alert('Failed to start scan: ' + err.message);
    }
  }

  function startPolling(projectId) {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    pollRef.current = setInterval(async () => {
      try {
        const scansRes = await fetch(`${API_URL}/projects/${projectId}/scans`);
        const data = await scansRes.json();
        const latest = data.scans?.[0];
        if (latest && latest.status !== 'in_progress') {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setScanningIds((prev) => {
            const next = new Set(prev);
            next.delete(projectId);
            return next;
          });
          loadProjects();
        }
      } catch (pollErr) {
        console.error('Polling error:', pollErr);
        clearInterval(pollRef.current);
        pollRef.current = null;
        setScanningIds((prev) => {
          const next = new Set(prev);
          next.delete(projectId);
          return next;
        });
      }
    }, 3000);
  }

  async function handleDeleteProject(projectOrId) {
    const id = typeof projectOrId === 'object' ? projectOrId.id : projectOrId;
    try {
      const res = await fetch(`${API_URL}/projects/${id}`, { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || 'Failed to delete project');
      }
      setScanningIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
      setSelectedProject((prev) => (prev && prev.id === id ? null : prev));
      loadProjects();
    } catch (err) {
      alert('Failed to delete: ' + err.message);
    }
  }

  async function handleDownloadFixed(project) {
    try {
      const scansRes = await fetch(`${API_URL}/projects/${project.id}/scans`);
      const scansData = await scansRes.json();
      const scans = scansData.scans || [];
      const latest = scans.find((s) => s.status === 'completed');
      if (!latest) {
        alert('No completed scan found. Run a scan first.');
        return;
      }

      // filesOriginal may be a JSON string or already parsed — normalize it
      let rawFiles = latest.filesOriginal;
      if (typeof rawFiles === 'string') {
        try { rawFiles = JSON.parse(rawFiles); } catch { rawFiles = null; }
      }
      if (!rawFiles || typeof rawFiles !== 'object' || Object.keys(rawFiles).length === 0) {
        alert('No file data available for this scan. Run a new scan to capture file contents.');
        return;
      }

      const files = Object.entries(rawFiles).map(([name, content]) => ({ name, content: String(content || '') }));

      // findings may be a JSON string or already parsed
      let findings = latest.findings;
      if (typeof findings === 'string') {
        try { findings = JSON.parse(findings); } catch { findings = []; }
      }

      const res = await fetch(`${API_URL}/download-fixed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files, findings: findings || [], folderName: project.name }),
      });
      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.error || `Server returned ${res.status}`);
      }
      const blob = await res.blob();
      if (!blob || blob.size === 0) throw new Error('Received empty response from server');
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${project.name}-fixed.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download fixed project: ' + err.message);
    }
  }

  if (selectedProject) {
    return (
      <section className="panel wide-panel">
        <RepoDetailView
          project={selectedProject}
          onBack={() => setSelectedProject(null)}
          onAutoScanToggle={handleAutoScanToggle}
          onProjectsChanged={loadProjects}
          onDeleteProject={handleDeleteProject}
          onRescan={handleRescan}
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
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginLeft: 'auto' }}>
          <button className="scan-btn" style={{ padding: '8px 14px', width: '180px', flexShrink: 0, whiteSpace: 'nowrap' }} onClick={() => setGhConfirmOpen(true)}>
            <GitBranch size={15} /> Login with GitHub
          </button>
          <button className="scan-btn" style={{ padding: '8px 14px', width: '180px', flexShrink: 0, whiteSpace: 'nowrap' }} onClick={() => setModalOpen(true)}>
            <Plus size={16} /> Connect Repository
          </button>
        </div>
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
                onDelete={handleDeleteProject}
                onDownloadFixed={handleDownloadFixed}
                isScanning={scanningIds.has(project.id)}
              />
            ))}
          </div>
        </>
      )}

      <ConnectRepoModal isOpen={modalOpen} onClose={() => setModalOpen(false)} onConnect={handleConnect} />

      {ghConfirmOpen && (
        <div className="modal-backdrop" onClick={() => setGhConfirmOpen(false)}>
          <div className="panel" style={{ maxWidth: '420px', width: '100%' }} onClick={(e) => e.stopPropagation()}>
            <div className="panel-head">
              <div className="panel-icon"><GitBranch size={18} /></div>
              <div><h2>Connect your GitHub account</h2></div>
            </div>
            <p style={{ fontSize: '13.5px', color: 'var(--text-dim)', margin: '0 0 18px', lineHeight: 1.6 }}>
              You will be redirected to GitHub to sign in and authorize SecureCode to access your repositories.
            </p>
            <div style={{ display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
              <button className="ghost-btn" style={{ padding: '8px 16px' }} onClick={() => setGhConfirmOpen(false)}>Cancel</button>
              <button className="scan-btn" style={{ padding: '8px 16px', width: 'auto' }} onClick={() => { setGhConfirmOpen(false); window.location.href = `${API_URL}/auth/github/login`; }}>Continue with GitHub</button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
