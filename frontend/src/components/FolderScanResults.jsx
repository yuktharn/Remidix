// FolderScanResults.jsx
// Displays scan results for folder uploads with a file tree on the left,
// side-by-side vulnerable/fixed code in the center, and issue details below.

import { useState, useMemo, useEffect, useRef } from 'react';
import {
  ChevronRight, ChevronDown, Folder, FolderOpen, FileCode2,
  AlertTriangle, CheckCircle2, Info, ShieldAlert, ShieldCheck,
  Copy, ExternalLink, Search, Download, ArrowLeft, RefreshCw,
  Trash2, Loader2, Lock, Globe, GitBranch, Clock,
} from 'lucide-react';
import {
  buildFileTree, sortedChildren, computeTreeAggregates,
  SEV_META, SEV_ORDER, normSev, sevMeta,
} from '../vulnLogic';
import PRCreationModal from './PRCreationModal';

const SEVERITY_BG = {
  Critical: 'rgba(255, 60, 95, 0.15)',
  High: 'rgba(255, 138, 61, 0.15)',
  Medium: 'rgba(245, 185, 66, 0.15)',
  Low: 'rgba(56, 189, 248, 0.15)',
  Info: 'rgba(167, 139, 250, 0.15)',
};

const API_URL = 'http://localhost:4000';

function formatDate(dateStr) {
  if (!dateStr) return 'Never';
  try { return new Date(dateStr).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }); }
  catch { return '—'; }
}

const LANG_MAP = {
  '.js': 'JavaScript', '.jsx': 'React JSX', '.ts': 'TypeScript', '.tsx': 'React TSX',
  '.py': 'Python', '.java': 'Java', '.rb': 'Ruby', '.go': 'Go', '.rs': 'Rust',
  '.php': 'PHP', '.c': 'C', '.cpp': 'C++', '.h': 'C/C++ Header', '.cs': 'C#',
  '.html': 'HTML', '.css': 'CSS', '.scss': 'SCSS', '.less': 'Less',
  '.json': 'JSON', '.yml': 'YAML', '.yaml': 'YAML', '.xml': 'XML',
  '.md': 'Markdown', '.sh': 'Shell', '.bash': 'Bash', '.sql': 'SQL',
  '.env': 'Environment', '.config': 'Config', '.toml': 'TOML', '.ini': 'INI',
};

function guessLanguage(path) {
  if (!path) return 'Unknown';
  const ext = '.' + path.split('.').pop().toLowerCase();
  return LANG_MAP[ext] || ext.replace('.', '').toUpperCase() || 'Unknown';
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

// Recursive file tree node with vulnerability badges and search filtering
function TreeNode({ node, depth, expanded, onToggle, selectedFile, onSelectFile, agg, searchQuery }) {
  const isDir = node.type === 'dir';
  const count = agg.count.get(node.path) || 0;
  const rank = agg.topRank.get(node.path);
  const badgeColor = rank != null ? Object.keys(SEV_ORDER).find((k) => SEV_ORDER[k] === rank) : null;
  const meta = badgeColor ? SEV_META[badgeColor] : null;
  const isOpen = expanded.has(node.path);
  const isSelected = !isDir && selectedFile === node.path;

  // Search filtering: show node if name matches or any descendant matches
  const matchesSearch = useMemo(() => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    // Match file/folder name
    if (node.name.toLowerCase().includes(q)) return true;
    // For directories, check if any descendant matches
    if (isDir && node.children) {
      return node.children.some((child) => {
        if (child.name.toLowerCase().includes(q)) return true;
        if (child.type === 'dir' && child.children) {
          return child.children.some((c) => c.name.toLowerCase().includes(q));
        }
        return false;
      });
    }
    return false;
  }, [searchQuery, node, isDir]);

  if (!matchesSearch) return null;

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
          color: isDir ? 'var(--text)' : 'var(--text)',
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
            <FileCode2 size={14} style={{ flexShrink: 0, color: count > 0 ? '#e2504a' : '#3ba7f0' }} />
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
          searchQuery={searchQuery}
        />
      ))}
    </div>
  );
}

export default function FolderScanResults({ scanData, onRescan, onNavigate, project, onBack, onDelete }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [expanded, setExpanded] = useState(() => new Set(['']));
  const [copiedSide, setCopiedSide] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIssueIdx, setSelectedIssueIdx] = useState(0);
  const [deleting, setDeleting] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [pushing, setPushing] = useState(false);
  const [pushResult, setPushResult] = useState(null);
  const [prModalOpen, setPrModalOpen] = useState(false);
  const [authUserId, setAuthUserId] = useState(null);
  const pollRef = useRef(null);
  const initExpandedRef = useRef(false);

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

  // Normalize scan data
  const data = useMemo(() => {
    if (!scanData) return null;

    let findings = [];
    if (Array.isArray(scanData.findings)) {
      findings = scanData.findings;
    } else if (typeof scanData.findings === 'string') {
      try {
        findings = JSON.parse(scanData.findings);
      } catch {
        findings = [];
      }
    }

    return {
      scanUid: scanData.scanUid || `scan_${scanData.id || 'current'}`,
      scannedAt: scanData.scannedAt ? new Date(scanData.scannedAt) : new Date(),
      fileName: project?.name || scanData.fileName || 'folder',
      totalFindings: scanData.totalFindings ?? scanData.total ?? findings.length,
      critical: scanData.criticalCount ?? scanData.critical ?? 0,
      high: scanData.highCount ?? scanData.highSeverity ?? scanData.high ?? 0,
      medium: scanData.mediumCount ?? scanData.mediumSeverity ?? scanData.medium ?? 0,
      low: scanData.lowCount ?? scanData.lowSeverity ?? scanData.low ?? 0,
      info: scanData.infoCount ?? scanData.info ?? 0,
      riskScore: scanData.riskScore ?? 0,
      securityScore: scanData.securityScore ?? Math.max(0, 100 - (scanData.riskScore ?? 0)),
      riskLevel: scanData.riskLevel || 'Low Risk',
      findings: findings.map((f, i) => ({
        ...f,
        id: f.id || i,
        index: i,
        severity: f.severity || 'Medium',
        line: f.line || 1,
        lineEnd: f.lineEnd || f.line || 1,
      })),
      fileTree: scanData.fileTree || null,
      filesCorrected: scanData.filesCorrected || null,
      filesOriginal: scanData.filesOriginal || null,
      findingsByFile: scanData.findingsByFile || null,
      scannedFiles: scanData.scannedFiles || [],
      treeTruncated: scanData.treeTruncated || false,
    };
  }, [scanData, project]);

  if (!data) {
    return (
      <div className="empty-state" style={{ padding: '60px 20px', textAlign: 'center' }}>
        <Folder size={56} className="empty-icon" style={{ opacity: 0.4, margin: '0 auto 16px' }} />
        <h3 style={{ fontSize: '20px', fontWeight: 600, color: '#f1f5f9' }}>
          {project ? 'No Scan Results' : 'No Folder Scan Results'}
        </h3>
        <p className="empty-sub" style={{ maxWidth: '440px', margin: '8px auto 20px', color: '#94a3b8' }}>
          {project
            ? 'Run a scan on this repository to view results.'
            : <>Upload a folder from the <strong>Code Scan</strong> tab and click <em>Run Security Scan</em> to view results.</>}
        </p>
        <button
          className="scan-btn"
          onClick={() => project ? (onBack && onBack()) : (onNavigate && onNavigate('Code Scan'))}
          style={{ margin: '0 auto' }}
        >
          {project ? 'Back to Projects' : 'Go to Code Scan'}
        </button>
      </div>
    );
  }

  // Build file tree from paths
  const tree = useMemo(() => {
    if (!data.fileTree) {
      const paths = Object.keys(data.findingsByFile || {}).map((p) => ({ path: p, type: 'file' }));
      return buildFileTree(paths);
    }
    // Flat array from repo scans — convert to nested tree node
    if (Array.isArray(data.fileTree)) return buildFileTree(data.fileTree);
    // Already a nested tree node (from folder scan endpoint)
    return data.fileTree;
  }, [data.fileTree, data.findingsByFile]);

  const agg = useMemo(() => computeTreeAggregates(data.findings), [data.findings]);

  const toggleDir = (path) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  // Auto-expand folders that contain findings (repo mode)
  useEffect(() => {
    if (!project || initExpandedRef.current || !data?.findings?.length) return;
    const next = new Set();
    for (const f of data.findings) {
      if (!f.fileName) continue;
      const parts = f.fileName.split('/');
      let acc = '';
      for (let i = 0; i < parts.length - 1; i++) { acc = acc ? `${acc}/${parts[i]}` : parts[i]; next.add(acc); }
    }
    setExpanded(next);
    initExpandedRef.current = true;
  }, [data, project]);

  // Reset issue selection when file changes
  useEffect(() => { setSelectedIssueIdx(0); }, [selectedFile]);

  // Get findings for selected file
  const fileFindings = useMemo(() => {
    if (!selectedFile || !data.findingsByFile) return [];
    return data.findingsByFile[selectedFile] || [];
  }, [selectedFile, data.findingsByFile]);

  // Get corrected code for selected file
  const correctedCode = useMemo(() => {
    if (!selectedFile || !data.filesCorrected) return null;
    return data.filesCorrected[selectedFile] || null;
  }, [selectedFile, data.filesCorrected]);

  // Get original file content for selected file
  const originalCode = useMemo(() => {
    if (!selectedFile || !data.filesOriginal) return null;
    return data.filesOriginal[selectedFile] || null;
  }, [selectedFile, data.filesOriginal]);

  // Compute which lines differ between original and corrected code
  const { vulnChangedLines, fixedChangedLines } = useMemo(() => {
    if (!originalCode || !correctedCode) return { vulnChangedLines: new Set(), fixedChangedLines: new Set() };
    const origLines = originalCode.split('\n');
    const corrLines = correctedCode.split('\n');
    const maxLen = Math.max(origLines.length, corrLines.length);
    const vulnSet = new Set();
    const fixedSet = new Set();
    for (let i = 0; i < maxLen; i++) {
      const left = origLines[i] || '';
      const right = corrLines[i] || '';
      if (left !== right) {
        if (i < origLines.length) vulnSet.add(i);
        if (i < corrLines.length) fixedSet.add(i);
      }
    }
    return { vulnChangedLines: vulnSet, fixedChangedLines: fixedSet };
  }, [originalCode, correctedCode]);

  // Findings for the selected file with display info
  const displayFindings = useMemo(() => {
    return fileFindings.map((f, i) => ({
      ...f,
      id: f.id || i,
      index: i,
    }));
  }, [fileFindings]);

  const handleCopy = (text, side) => {
    navigator.clipboard.writeText(text);
    setCopiedSide(side);
    setTimeout(() => setCopiedSide(null), 2000);
  };

  async function handleRescanWrapper() {
    if (rescanning) return;
    setRescanning(true);
    try {
      await onRescan?.();
    } finally {
      setRescanning(false);
    }
  }

  async function handleDeleteWrapper() {
    if (!window.confirm(`Delete "${data.fileName}" from SecureCode? This will not affect the actual GitHub repository.`)) return;
    setDeleting(true);
    try {
      await onDelete?.(project.id);
    } finally {
      setDeleting(false);
    }
  }

  async function handlePushToGitHub() {
    if (pushing) return;
    if (!data.filesCorrected || Object.keys(data.filesCorrected).length === 0) {
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
      const files = Object.entries(data.filesCorrected).map(([path, content]) => ({ path, content: String(content || '') }));

      // Resolve owner/repo: prefer direct fields, then parse from URL
      let owner = project?.githubOwner || project?.github_owner || null;
      let repo  = project?.githubRepo  || project?.github_repo  || null;
      if (!owner || !repo) {
        const rawUrl = project?.repos?.[0]?.url || project?.githubUrl || project?.github_url || '';
        const m = rawUrl.match(/github\.com[/:]([^/]+)\/([^/.]+)/i);
        if (m) { owner = m[1]; repo = m[2]; }
      }
      if (!owner || !repo) {
        throw new Error('Could not identify GitHub owner/repo. Make sure the project has a valid GitHub repository URL.');
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
          baseBranch: project?.repos?.[0]?.branch || 'main',
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
      const result = await res.json();
      setPushResult(result);
    } catch (err) {
      alert('Push failed: ' + err.message);
    } finally {
      setPushing(false);
    }
  }

  const handleDownloadOriginal = async () => {
    if (!data.filesOriginal) return;
    const files = Object.entries(data.filesOriginal).map(([name, content]) => ({ name, content }));
    const folderName = project?.name || data.fileName;
    try {
      const res = await fetch(`${API_URL}/download-original`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files, folderName }),
      });
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${folderName || 'project'}-original.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download original failed:', err);
    }
  };

  const handleDownloadFixed = async () => {
    if (!data.filesOriginal) return;
    const files = Object.entries(data.filesOriginal).map(([name, content]) => ({ name, content }));
    const folderName = project?.name || data.fileName;
    try {
      const res = await fetch(`${API_URL}/download-fixed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files, findings: data.findings, folderName }),
      });
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${folderName || 'project'}-fixed.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download fixed failed:', err);
    }
  };

  const repoUrl = project?.repos?.[0]?.url || '';
  const branch = project?.repos?.[0]?.branch || 'main';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Repo-specific header — only shown when `project` prop is provided */}
      {project && (
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', flexWrap: 'wrap' }}>
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
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}><Clock size={12} /> Scanned: {formatDate(scanData?.scannedAt)}</span>
              {repoUrl && (
                <a href={repoUrl.startsWith('http') ? repoUrl : `https://${repoUrl}`} target="_blank" rel="noreferrer" style={{ color: '#7ec3f5', display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
                  <ExternalLink size={12} /> Open repo
                </a>
              )}
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <button className="scan-btn" style={{ padding: '8px 14px' }} onClick={handleRescanWrapper} disabled={rescanning}>
              {rescanning ? <><Loader2 size={14} className="spin" /> Scanning…</> : <><RefreshCw size={14} /> Rescan</>}
            </button>
            <button className="ghost-btn" onClick={handleDownloadOriginal} style={{ padding: '6px 12px' }}>
              <Download size={13} /> Original
            </button>
            <button className="ghost-btn" onClick={handleDownloadFixed} style={{ padding: '6px 12px', borderColor: 'rgba(79,208,138,0.3)', color: '#4fd08a' }}>
              <Download size={13} /> Fixed
            </button>
            {project && data.filesCorrected && Object.keys(data.filesCorrected).length > 0 && (() => {
              return (
                <>
                  <button className="ghost-btn" onClick={handlePushToGitHub} disabled={pushing} style={{ padding: '6px 12px', color: '#7ec3f5' }}>
                    {pushing ? <><Loader2 size={13} className="spin" /> Pushing…</> : <><ExternalLink size={13} /> Push to GitHub</>}
                  </button>
                  <button className="ghost-btn" onClick={() => setPrModalOpen(true)} style={{ padding: '6px 12px', color: '#a78bfa' }}>
                    <GitBranch size={13} /> Create PR
                  </button>
                </>
              );
            })()}
            {pushResult && (
              <div style={{ position: 'absolute', top: '100%', right: '60px', marginTop: '8px', padding: '10px 14px', background: 'var(--panel)', border: '1px solid rgba(79,208,138,0.4)', borderRadius: '8px', fontSize: '12px', zIndex: 10, minWidth: '220px', boxShadow: '0 4px 12px rgba(0,0,0,0.3)' }}>
                <div style={{ color: '#4fd08a', fontWeight: 600, marginBottom: '4px' }}>Pushed successfully!</div>
                <div>Branch: <span style={{ fontFamily: 'monospace' }}>{pushResult.branch}</span></div>
                {pushResult.url && <a href={pushResult.url} target="_blank" rel="noreferrer" style={{ color: '#7ec3f5', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '4px' }}><ExternalLink size={11} /> View on GitHub</a>}
                <button className="text-btn" style={{ marginTop: '6px', fontSize: '11px' }} onClick={() => setPushResult(null)}>Dismiss</button>
              </div>
            )}
            <button className="icon-btn" onClick={handleDeleteWrapper} disabled={deleting} title="Delete repository" style={{ color: '#e2504a' }}>
              {deleting ? <Loader2 size={15} className="spin" /> : <Trash2 size={15} />}
            </button>
          </div>
        </div>
      )}

      {/* Summary bar */}
      <section className="panel" style={{ marginBottom: '0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <ShieldCheck size={18} style={{ color: '#4fd08a' }} />
          <span style={{ fontWeight: 600, fontSize: '14px' }}>
            {project ? 'Scan Complete' : 'Folder Scan Complete'}
          </span>
          {!project && <span style={{ opacity: 0.6, fontSize: '12px' }}>{data.fileName}</span>}
          <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px', alignItems: 'center' }}>
            {[
              { label: 'Critical', count: data.critical, color: '#ff3c5f' },
              { label: 'High', count: data.high, color: '#ff8a3d' },
              { label: 'Medium', count: data.medium, color: '#f5b942' },
              { label: 'Low', count: data.low, color: '#38bdf8' },
              { label: 'Info', count: data.info, color: '#a78bfa' },
            ].filter(s => s.count > 0).map(s => (
              <span
                key={s.label}
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '999px',
                  color: s.color,
                  background: SEVERITY_BG[s.label],
                  border: `1px solid ${s.color}33`,
                }}
              >
                {s.count} {s.label}
              </span>
            ))}
            {!project && (
              <div style={{ display: 'flex', gap: '6px', marginLeft: '8px' }}>
                <button
                  onClick={handleDownloadOriginal}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '4px',
                    padding: '4px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.12)',
                    background: 'rgba(255,255,255,0.05)', color: 'var(--text)', fontSize: '11px',
                    cursor: 'pointer', fontWeight: 500,
                  }}
                >
                  <Download size={12} /> Original
                </button>
                <button
                  onClick={handleDownloadFixed}
                  style={{
                    display: 'flex', alignItems: 'center', gap: '4px',
                    padding: '4px 10px', borderRadius: '6px', border: '1px solid rgba(79,208,138,0.3)',
                    background: 'rgba(79,208,138,0.1)', color: '#4fd08a', fontSize: '11px',
                    cursor: 'pointer', fontWeight: 600,
                  }}
                >
                  <Download size={12} /> Fixed
                </button>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* Main content: file tree + code diff + metadata sidebar */}
      <div style={{ display: 'grid', gridTemplateColumns: '260px minmax(0, 1fr) 260px', gap: '14px', width: '100%', minWidth: 0, overflow: 'hidden' }}>
        {/* File tree with search */}
        <section className="panel" style={{ maxHeight: '600px', overflow: 'auto', minWidth: 0 }}>
          <div style={{ padding: '8px', fontWeight: 600, fontSize: '13px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            {project ? 'Repository Files' : 'Project Files'} ({data.filesCorrected ? Object.keys(data.filesCorrected).length : Object.keys(data.findingsByFile || {}).length})
          </div>
          <div style={{ padding: '6px 8px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 8px', background: 'rgba(255,255,255,0.04)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <Search size={12} style={{ opacity: 0.5 }} />
              <input
                type="text"
                placeholder="Search files or folders..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{ background: 'none', border: 'none', outline: 'none', color: 'var(--text)', fontSize: '12px', width: '100%' }}
              />
            </div>
          </div>
          <div style={{ padding: '4px' }}>
            {sortedChildren(tree).map((child) => (
              <TreeNode
                key={child.path}
                node={child}
                depth={0}
                expanded={expanded}
                onToggle={toggleDir}
                selectedFile={selectedFile}
                onSelectFile={setSelectedFile}
                agg={agg}
                searchQuery={searchQuery}
              />
            ))}
          </div>
        </section>

        {/* Code diff / Finding details */}
        <section className="panel" style={{ minHeight: '400px', minWidth: 0, overflow: 'hidden' }}>
          {!selectedFile ? (
            <div className="empty-state" style={{ padding: '60px 20px', textAlign: 'center' }}>
              <FileCode2 size={48} className="empty-icon" style={{ opacity: 0.4, margin: '0 auto 16px' }} />
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#f1f5f9' }}>Select a file to view details</h3>
              <p className="empty-sub" style={{ maxWidth: '360px', margin: '8px auto 0', color: '#94a3b8' }}>
                Click on a file in the tree to see its vulnerabilities and suggested fixes.
              </p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              {/* File header */}
              <div style={{
                padding: '10px 14px',
                borderBottom: '1px solid rgba(255,255,255,0.06)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
              }}>
                <FileCode2 size={14} style={{ color: '#3ba7f0' }} />
                <span style={{ fontWeight: 600, fontSize: '13px' }}>{selectedFile}</span>
                <span style={{ marginLeft: 'auto', fontSize: '11px', opacity: 0.6 }}>
                  {fileFindings.length} {fileFindings.length === 1 ? 'issue' : 'issues'}
                </span>
              </div>

              {/* Side-by-side complete file view */}
              {originalCode && correctedCode && (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', borderBottom: '1px solid rgba(255,255,255,0.06)', minWidth: 0, overflow: 'hidden' }}>
                  {/* Vulnerable Code */}
                  <div style={{ borderRight: '1px solid rgba(255,255,255,0.06)', minWidth: 0, overflow: 'hidden' }}>
                    <div style={{ padding: '6px 12px', fontSize: '11px', fontWeight: 600, color: '#ff3c5f', background: 'rgba(255,60,95,0.06)' }}>
                      Vulnerable Code
                    </div>
                    <div style={{ maxHeight: '400px', overflow: 'auto' }}>
                      {originalCode.split('\n').map((line, idx) => {
                        const lineNum = idx + 1;
                        const isVulnerable = vulnChangedLines.has(idx);
                        return (
                          <div key={idx} style={{
                            display: 'flex',
                            fontFamily: 'monospace',
                            fontSize: '11.5px',
                            lineHeight: '1.6',
                            background: isVulnerable ? 'rgba(255,60,95,0.12)' : 'transparent',
                            borderLeft: isVulnerable ? '3px solid #ff3c5f' : '3px solid transparent',
                          }}>
                            <span style={{
                              width: '36px',
                              flexShrink: 0,
                              textAlign: 'right',
                              padding: '0 8px',
                              color: isVulnerable ? '#ff3c5f' : 'var(--text-faint)',
                              userSelect: 'none',
                              fontSize: '10.5px',
                            }}>{lineNum}</span>
                            <span style={{ flex: 1, padding: '0 8px', whiteSpace: 'pre', overflow: 'hidden' }}>{line}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  {/* Fixed Code */}
                  <div style={{ minWidth: 0, overflow: 'hidden' }}>
                    <div style={{ padding: '6px 12px', fontSize: '11px', fontWeight: 600, color: '#4fd08a', background: 'rgba(79,208,138,0.06)' }}>
                      Fixed &amp; Secure Code
                    </div>
                    <div style={{ maxHeight: '400px', overflow: 'auto' }}>
                      {correctedCode.split('\n').map((line, idx) => {
                        const lineNum = idx + 1;
                        const isFixed = fixedChangedLines.has(idx);
                        return (
                          <div key={idx} style={{
                            display: 'flex',
                            fontFamily: 'monospace',
                            fontSize: '11.5px',
                            lineHeight: '1.6',
                            background: isFixed ? 'rgba(79,208,138,0.12)' : 'transparent',
                            borderLeft: isFixed ? '3px solid #4fd08a' : '3px solid transparent',
                          }}>
                            <span style={{
                              width: '36px',
                              flexShrink: 0,
                              textAlign: 'right',
                              padding: '0 8px',
                              color: isFixed ? '#4fd08a' : 'var(--text-faint)',
                              userSelect: 'none',
                              fontSize: '10.5px',
                            }}>{lineNum}</span>
                            <span style={{ flex: 1, padding: '0 8px', whiteSpace: 'pre', overflow: 'hidden' }}>{line}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {/* Issue Details */}
              <div style={{ flex: 1, overflow: 'auto', padding: '8px' }}>
                {displayFindings.length === 0 ? (
                  <div style={{ padding: '20px', textAlign: 'center', color: '#4fd08a' }}>
                    <CheckCircle2 size={20} style={{ marginBottom: '8px' }} />
                    <div style={{ fontSize: '13px' }}>No issues found in this file</div>
                  </div>
                ) : (
                  displayFindings.map((finding) => {
                    const sev = normSev(finding.severity);
                    const meta = sevMeta(sev);
                    return (
                      <div
                        key={finding.id}
                        style={{
                          marginBottom: '12px',
                          border: `1px solid ${meta.border}`,
                          borderRadius: '8px',
                          overflow: 'hidden',
                        }}
                      >
                        {/* Finding header */}
                        <div style={{
                          padding: '10px 12px',
                          background: meta.bg,
                          display: 'flex',
                          alignItems: 'center',
                          gap: '8px',
                        }}>
                          <span style={{
                            fontSize: '10px',
                            fontWeight: 700,
                            padding: '2px 6px',
                            borderRadius: '4px',
                            color: meta.color,
                            background: meta.bg,
                            border: `1px solid ${meta.border}`,
                          }}>
                            {sev}
                          </span>
                          <span style={{ fontWeight: 600, fontSize: '13px', color: meta.color }}>
                            {finding.type}
                          </span>
                          <span style={{ fontSize: '11px', opacity: 0.6, marginLeft: 'auto' }}>
                            Line {finding.line}{finding.lineEnd !== finding.line ? `-${finding.lineEnd}` : ''}
                          </span>
                        </div>

                        {/* Finding details */}
                        <div style={{ padding: '10px 12px', fontSize: '12.5px' }}>
                          {finding.explanation && (
                            <div style={{ marginBottom: '8px', color: 'var(--text)' }}>
                              <strong>Description:</strong> {finding.explanation}
                            </div>
                          )}
                          {finding.impact && (
                            <div style={{ marginBottom: '8px', color: 'var(--text)' }}>
                              <strong>Impact:</strong> {finding.impact}
                            </div>
                          )}
                          {finding.fix && (
                            <div style={{ marginBottom: '8px', color: 'var(--text)' }}>
                              <strong>Recommendation:</strong> {finding.fix}
                            </div>
                          )}

                          {/* Vulnerable code snippet */}
                          {finding.vulnerableCode && (
                            <div style={{ marginBottom: '8px' }}>
                              <div style={{ fontSize: '11px', fontWeight: 600, color: '#ff3c5f', marginBottom: '4px' }}>
                                Vulnerable Line(s):
                              </div>
                              <pre style={{
                                margin: 0,
                                padding: '8px',
                                background: 'rgba(255,60,95,0.08)',
                                border: '1px solid rgba(255,60,95,0.2)',
                                borderRadius: '6px',
                                fontSize: '11.5px',
                                lineHeight: '1.5',
                                overflow: 'auto',
                                fontFamily: 'monospace',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                              }}>
                                {finding.vulnerableCode}
                              </pre>
                            </div>
                          )}

                          {/* Corrected code snippet */}
                          {finding.correctedCode && (
                            <div style={{ marginBottom: '8px' }}>
                              <div style={{ fontSize: '11px', fontWeight: 600, color: '#4fd08a', marginBottom: '4px' }}>
                                Secure Fix:
                              </div>
                              <pre style={{
                                margin: 0,
                                padding: '8px',
                                background: 'rgba(79,208,138,0.08)',
                                border: '1px solid rgba(79,208,138,0.2)',
                                borderRadius: '6px',
                                fontSize: '11.5px',
                                lineHeight: '1.5',
                                overflow: 'auto',
                                fontFamily: 'monospace',
                                whiteSpace: 'pre-wrap',
                                wordBreak: 'break-word',
                              }}>
                                {finding.correctedCode}
                              </pre>
                            </div>
                          )}

                          {/* CWE / OWASP references */}
                          {(finding.cwe || finding.owasp) && (
                            <div style={{ display: 'flex', gap: '12px', fontSize: '11px', color: 'var(--text-faint)', marginTop: '4px' }}>
                              {finding.cwe && <span>Reference: {finding.cwe}</span>}
                              {finding.owasp && <span>OWASP: {finding.owasp}</span>}
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })
                )}
              </div>
            </div>
          )}
        </section>

        {/* Right sidebar: file metadata & selected issue */}
        <section className="panel" style={{ maxHeight: '600px', overflow: 'auto', minWidth: 0 }}>
          {!selectedFile ? (
            <div style={{ padding: '40px 14px', textAlign: 'center', color: 'var(--text-faint)', fontSize: '12px' }}>
              Select a file to view details
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {/* File metadata */}
              <div style={{ padding: '10px 12px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
                <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-faint)', marginBottom: '6px' }}>
                  File Details
                </div>
                <div style={{ display: 'grid', gap: '6px' }}>
                  <div style={{ fontSize: '11px' }}>
                    <span style={{ color: 'var(--text-faint)' }}>Path: </span>
                    <span style={{ color: 'var(--text)', fontFamily: 'monospace', fontSize: '10.5px', wordBreak: 'break-all' }}>{selectedFile}</span>
                  </div>
                  <div style={{ fontSize: '11px' }}>
                    <span style={{ color: 'var(--text-faint)' }}>Language: </span>
                    <span style={{ color: 'var(--text)' }}>{guessLanguage(selectedFile)}</span>
                  </div>
                  <div style={{ fontSize: '11px' }}>
                    <span style={{ color: 'var(--text-faint)' }}>Lines: </span>
                    <span style={{ color: 'var(--text)' }}>{originalCode ? originalCode.split('\n').length : '—'}</span>
                  </div>
                  <div style={{ fontSize: '11px' }}>
                    <span style={{ color: 'var(--text-faint)' }}>Size: </span>
                    <span style={{ color: 'var(--text)' }}>{originalCode ? formatBytes(originalCode.length) : '—'}</span>
                  </div>
                  <div style={{ fontSize: '11px' }}>
                    <span style={{ color: 'var(--text-faint)' }}>Issues: </span>
                    <span style={{ color: fileFindings.length > 0 ? '#ff3c5f' : '#4fd08a', fontWeight: 600 }}>
                      {fileFindings.length}
                    </span>
                  </div>
                </div>
              </div>

              {/* Selected issue details */}
              {fileFindings.length > 0 && (
                <div style={{ padding: '0 12px 12px' }}>
                  <div style={{ fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-faint)', marginBottom: '6px' }}>
                    Selected Issue
                  </div>
                  <select
                    value={selectedIssueIdx}
                    onChange={(e) => setSelectedIssueIdx(Number(e.target.value))}
                    style={{
                      width: '100%',
                      padding: '6px 8px',
                      borderRadius: '6px',
                      border: '1px solid rgba(255,255,255,0.1)',
                      background: 'var(--panel)',
                      color: 'var(--text)',
                      fontSize: '12px',
                      marginBottom: '8px',
                    }}
                  >
                    {displayFindings.map((f, i) => (
                      <option key={f.id} value={i}>
                        {normSev(f.severity)}: {f.type} (L{f.line})
                      </option>
                    ))}
                  </select>
                  {displayFindings[selectedIssueIdx] && (
                    <div style={{ fontSize: '11px', lineHeight: '1.5' }}>
                      <div style={{ marginBottom: '6px' }}>
                        <span style={{ color: 'var(--text-faint)' }}>Severity: </span>
                        <span style={{ color: sevMeta(normSev(displayFindings[selectedIssueIdx].severity)).color, fontWeight: 600 }}>
                          {normSev(displayFindings[selectedIssueIdx].severity)}
                        </span>
                      </div>
                      <div style={{ marginBottom: '6px' }}>
                        <span style={{ color: 'var(--text-faint)' }}>Line: </span>
                        <span style={{ color: 'var(--text)' }}>{displayFindings[selectedIssueIdx].line}</span>
                      </div>
                      {displayFindings[selectedIssueIdx].cwe && (
                        <div style={{ marginBottom: '6px' }}>
                          <span style={{ color: 'var(--text-faint)' }}>CWE: </span>
                          <span style={{ color: 'var(--text)' }}>{displayFindings[selectedIssueIdx].cwe}</span>
                        </div>
                      )}
                      {displayFindings[selectedIssueIdx].owasp && (
                        <div style={{ marginBottom: '6px' }}>
                          <span style={{ color: 'var(--text-faint)' }}>OWASP: </span>
                          <span style={{ color: 'var(--text)' }}>{displayFindings[selectedIssueIdx].owasp}</span>
                        </div>
                      )}
                      {displayFindings[selectedIssueIdx].explanation && (
                        <div style={{ marginTop: '8px', padding: '8px', background: 'rgba(255,255,255,0.03)', borderRadius: '6px', fontSize: '11px', color: 'var(--text)' }}>
                          {displayFindings[selectedIssueIdx].explanation}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </section>
      </div>

      {project && (
        <PRCreationModal
          isOpen={prModalOpen}
          onClose={() => setPrModalOpen(false)}
          project={project}
          findings={data?.findings || []}
          filesOriginal={data?.filesOriginal || {}}
          filesCorrected={data?.filesCorrected || {}}
        />
      )}
    </div>
  );
}
