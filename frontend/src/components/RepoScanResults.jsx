// RepoScanResults.jsx
// Repository-specific scan results view — same 3-column layout as FolderScanResults.
// Shows file tree, side-by-side vulnerable/fixed code, and issue metadata for a
// connected GitHub/GitLab repository.

import { useState, useMemo, useEffect, useRef } from 'react';
import {
  ChevronRight, ChevronDown, Folder, FolderOpen, FileCode2,
  AlertTriangle, CheckCircle2, ShieldAlert, ShieldCheck,
  Search, Download, ArrowLeft, RefreshCw, Trash2, Loader2,
  ExternalLink, Lock, Globe, GitBranch, Clock, Send,
} from 'lucide-react';
import {
  buildFileTree, sortedChildren, computeTreeAggregates,
  SEV_META, SEV_ORDER, normSev, sevMeta,
} from '../vulnLogic';
import PRCreationModal from './PRCreationModal';

const API_URL = 'https://remidix-backend.onrender.com';

const SEVERITY_BG = {
  Critical: 'rgba(255, 60, 95, 0.15)',
  High: 'rgba(255, 138, 61, 0.15)',
  Medium: 'rgba(245, 185, 66, 0.15)',
  Low: 'rgba(56, 189, 248, 0.15)',
  Info: 'rgba(167, 139, 250, 0.15)',
};

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

function formatDate(d) {
  if (!d) return '—';
  try { return new Date(d).toLocaleDateString(); } catch { return '—'; }
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

  const matchesSearch = useMemo(() => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    if (node.name.toLowerCase().includes(q)) return true;
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
          display: 'flex', alignItems: 'center', gap: '6px',
          padding: '4px 8px', paddingLeft: `${8 + depth * 14}px`,
          borderRadius: '6px', cursor: 'pointer',
          background: isSelected ? 'rgba(169,140,240,0.14)' : 'transparent',
          border: isSelected ? '1px solid rgba(169,140,240,0.4)' : '1px solid transparent',
          fontSize: '12.5px', color: 'var(--text)',
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
              flexShrink: 0, fontSize: '10.5px', fontWeight: 700, minWidth: '18px',
              textAlign: 'center', padding: '1px 6px', borderRadius: '999px',
              color: meta.color, background: meta.bg, border: `1px solid ${meta.border}`,
            }}
            title={`${count} ${count === 1 ? 'issue' : 'issues'}`}
          >
            {count}
          </span>
        )}
      </div>
      {isDir && isOpen && sortedChildren(node).map((child) => (
        <TreeNode
          key={child.path} node={child} depth={depth + 1}
          expanded={expanded} onToggle={onToggle}
          selectedFile={selectedFile} onSelectFile={onSelectFile}
          agg={agg} searchQuery={searchQuery}
        />
      ))}
    </div>
  );
}

export default function RepoScanResults({ project, scanData, onBack, onRescan, onDelete }) {
  const [selectedFile, setSelectedFile] = useState(null);
  const [expanded, setExpanded] = useState(() => new Set(['']));
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedIssueIdx, setSelectedIssueIdx] = useState(0);
  const [deleting, setDeleting] = useState(false);
  const [rescanning, setRescanning] = useState(false);
  const [showPRModal, setShowPRModal] = useState(false);
  const pollRef = useRef(null);

  // Normalize scan data
  const data = useMemo(() => {
    if (!scanData) return null;
    let findings = [];
    if (Array.isArray(scanData.findings)) findings = scanData.findings;
    else if (typeof scanData.findings === 'string') {
      try { findings = JSON.parse(scanData.findings); } catch { findings = []; }
    }
    return {
      scanUid: scanData.id || 'current',
      scannedAt: scanData.scannedAt,
      fileName: project?.name || 'repository',
      totalFindings: scanData.total ?? findings.length,
      critical: scanData.critical ?? 0,
      high: scanData.high ?? 0,
      medium: scanData.medium ?? 0,
      low: scanData.low ?? 0,
      info: scanData.info ?? 0,
      riskScore: scanData.riskScore ?? 0,
      securityScore: scanData.securityScore ?? Math.max(0, 100 - (scanData.riskScore ?? 0)),
      riskLevel: scanData.riskLevel || 'Low Risk',
      findings: findings.map((f, i) => ({
        ...f, id: f.id || i, index: i,
        severity: f.severity || 'Medium',
        line: f.line || 1, lineEnd: f.lineEnd || f.line || 1,
      })),
      fileTree: scanData.fileTree || null,
      filesCorrected: scanData.filesCorrected || null,
      filesOriginal: scanData.filesOriginal || null,
      findingsByFile: scanData.findingsByFile || null,
      scannedFiles: scanData.scannedFiles || [],
      treeTruncated: scanData.treeTruncated || false,
    };
  }, [scanData, project]);

  // Build file tree
  const tree = useMemo(() => {
    if (data?.fileTree) return data.fileTree;
    const paths = Object.keys(data?.findingsByFile || {}).map((p) => ({ path: p, type: 'file' }));
    return buildFileTree(paths);
  }, [data]);

  const agg = useMemo(() => computeTreeAggregates(data?.findings || []), [data]);

  const toggleDir = (path) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path); else next.add(path);
      return next;
    });
  };

  // Auto-expand folders with findings
  useEffect(() => {
    if (!data?.findings?.length) return;
    const next = new Set();
    for (const f of data.findings) {
      if (!f.fileName) continue;
      const parts = f.fileName.split('/');
      let acc = '';
      for (let i = 0; i < parts.length - 1; i++) { acc = acc ? `${acc}/${parts[i]}` : parts[i]; next.add(acc); }
    }
    setExpanded(next);
  }, [data]);

  const fileFindings = useMemo(() => {
    if (!selectedFile || !data?.findingsByFile) return [];
    return data.findingsByFile[selectedFile] || [];
  }, [selectedFile, data]);

  const correctedCode = useMemo(() => {
    if (!selectedFile || !data?.filesCorrected) return null;
    return data.filesCorrected[selectedFile] || null;
  }, [selectedFile, data]);

  const originalCode = useMemo(() => {
    if (!selectedFile || !data?.filesOriginal) return null;
    return data.filesOriginal[selectedFile] || null;
  }, [selectedFile, data]);

  const displayFindings = useMemo(() => {
    return fileFindings.map((f, i) => ({ ...f, id: f.id || i, index: i }));
  }, [fileFindings]);

  // Reset issue selection when file changes
  useEffect(() => { setSelectedIssueIdx(0); }, [selectedFile]);

  async function handleRescan() {
    if (rescanning) return;
    setRescanning(true);
    try {
      await onRescan?.();
    } finally {
      setRescanning(false);
    }
  }

  async function handleDelete() {
    if (!window.confirm(`Delete "${project.name}" from SecureCode? This will not affect the actual GitHub repository.`)) return;
    setDeleting(true);
    try {
      await onDelete?.(project.id);
    } finally {
      setDeleting(false);
    }
  }

  const handleDownloadOriginal = async () => {
    if (!data?.filesOriginal) return;
    const files = Object.entries(data.filesOriginal).map(([name, content]) => ({ name, content }));
    try {
      const res = await fetch(`${API_URL}/download-original`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files, folderName: project?.name || 'repository' }),
      });
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${project?.name || 'repository'}-original.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download original failed:', err);
    }
  };

  const handleDownloadFixed = async () => {
    if (!data?.filesOriginal) return;
    const files = Object.entries(data.filesOriginal).map(([name, content]) => ({ name, content }));
    try {
      const res = await fetch(`${API_URL}/download-fixed`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ files, findings: data.findings, folderName: project?.name || 'repository' }),
      });
      if (!res.ok) throw new Error('Download failed');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${project?.name || 'repository'}-fixed.zip`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Download fixed failed:', err);
    }
  };

  if (!data) {
    return (
      <div className="empty-state" style={{ padding: '60px 20px', textAlign: 'center' }}>
        <Folder size={56} className="empty-icon" style={{ opacity: 0.4, margin: '0 auto 16px' }} />
        <h3 style={{ fontSize: '20px', fontWeight: 600, color: '#f1f5f9' }}>No Scan Results</h3>
        <p className="empty-sub" style={{ maxWidth: '440px', margin: '8px auto 20px', color: '#94a3b8' }}>
          Run a scan on this repository to view results.
        </p>
        <button className="scan-btn" onClick={onBack} style={{ margin: '0 auto' }}>
          Back to Projects
        </button>
      </div>
    );
  }

  const repoUrl = project?.repos?.[0]?.url || '';
  const branch = project?.repos?.[0]?.branch || 'main';

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: '12px', flexWrap: 'wrap' }}>
        <button className="icon-btn" onClick={onBack} aria-label="Back to projects">
          <ArrowLeft size={16} />
        </button>
        <div style={{ flex: 1, minWidth: '220px' }}>
          <h2 style={{ margin: '0 0 6px', fontSize: '19px', display: 'flex', alignItems: 'center', gap: '9px' }}>
            <Folder size={18} style={{ color: '#3ba7f0' }} /> {project?.name}
          </h2>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap', fontSize: '12px', color: 'var(--text-faint)' }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              {project?.isPrivate ? <Lock size={12} /> : <Globe size={12} />}{project?.isPrivate ? 'Private' : 'Public'}
            </span>
            <span>·</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}><GitBranch size={12} /> {project?.platform}</span>
            <span>·</span>
            <span>{branch}</span>
            <span>·</span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}><Clock size={12} /> Scanned: {formatDate(data.scannedAt)}</span>
            {repoUrl && (
              <a href={repoUrl.startsWith('http') ? repoUrl : `https://${repoUrl}`} target="_blank" rel="noreferrer" style={{ color: '#7ec3f5', display: 'inline-flex', alignItems: 'center', gap: '3px' }}>
                <ExternalLink size={12} /> Open repo
              </a>
            )}
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button className="scan-btn" style={{ padding: '8px 14px' }} onClick={handleRescan} disabled={rescanning}>
            {rescanning ? <><Loader2 size={14} className="spin" /> Scanning…</> : <><RefreshCw size={14} /> Rescan</>}
          </button>
          {data?.findings?.length > 0 && (
            <button
              className="scan-btn" style={{ padding: '8px 14px', background: '#a78bfa' }}
              onClick={() => setShowPRModal(true)}
            >
              <Send size={13} /> Create Fix PR
            </button>
          )}
          <button className="ghost-btn" onClick={handleDownloadOriginal} style={{ padding: '6px 12px' }}>
            <Download size={13} /> Original
          </button>
          <button className="ghost-btn" onClick={handleDownloadFixed} style={{ padding: '6px 12px', borderColor: 'rgba(79,208,138,0.3)', color: '#4fd08a' }}>
            <Download size={13} /> Fixed
          </button>
          <button className="icon-btn" onClick={handleDelete} disabled={deleting} title="Delete repository" style={{ color: '#e2504a' }}>
            {deleting ? <Loader2 size={15} className="spin" /> : <Trash2 size={15} />}
          </button>
        </div>
      </div>

      {/* Summary bar */}
      <section className="panel" style={{ marginBottom: '0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <ShieldCheck size={18} style={{ color: '#4fd08a' }} />
          <span style={{ fontWeight: 600, fontSize: '14px' }}>Scan Complete</span>
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
                  fontSize: '11px', fontWeight: 700, padding: '2px 8px', borderRadius: '999px',
                  color: s.color, background: SEVERITY_BG[s.label], border: `1px solid ${s.color}33`,
                }}
              >
                {s.count} {s.label}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* Main content: file tree + code diff + metadata sidebar */}
      <div style={{ display: 'grid', gridTemplateColumns: '260px minmax(0, 1fr) 260px', gap: '14px', width: '100%', minWidth: 0, overflow: 'hidden' }}>
        {/* File tree with search */}
        <section className="panel" style={{ maxHeight: '600px', overflow: 'auto', minWidth: 0 }}>
          <div style={{ padding: '8px', fontWeight: 600, fontSize: '13px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            Repository Files ({data.filesCorrected ? Object.keys(data.filesCorrected).length : Object.keys(data.findingsByFile || {}).length})
          </div>
          <div style={{ padding: '6px 8px', borderBottom: '1px solid rgba(255,255,255,0.06)' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', padding: '4px 8px', background: 'rgba(255,255,255,0.04)', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <Search size={12} style={{ opacity: 0.5 }} />
              <input
                type="text" placeholder="Search files or folders..."
                value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
                style={{ background: 'none', border: 'none', outline: 'none', color: 'var(--text)', fontSize: '12px', width: '100%' }}
              />
            </div>
          </div>
          <div style={{ padding: '4px' }}>
            {sortedChildren(tree).map((child) => (
              <TreeNode
                key={child.path} node={child} depth={0}
                expanded={expanded} onToggle={toggleDir}
                selectedFile={selectedFile} onSelectFile={setSelectedFile}
                agg={agg} searchQuery={searchQuery}
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
                padding: '10px 14px', borderBottom: '1px solid rgba(255,255,255,0.06)',
                display: 'flex', alignItems: 'center', gap: '8px',
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
                        const isVulnerable = fileFindings.some((f) => lineNum >= (f.line || 0) && lineNum <= (f.lineEnd || f.line || 0));
                        return (
                          <div key={idx} style={{
                            display: 'flex', fontFamily: 'monospace', fontSize: '11.5px', lineHeight: '1.6',
                            background: isVulnerable ? 'rgba(255,60,95,0.12)' : 'transparent',
                            borderLeft: isVulnerable ? '3px solid #ff3c5f' : '3px solid transparent',
                          }}>
                            <span style={{
                              width: '36px', flexShrink: 0, textAlign: 'right', padding: '0 8px',
                              color: isVulnerable ? '#ff3c5f' : 'var(--text-faint)', userSelect: 'none', fontSize: '10.5px',
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
                        const isFixed = fileFindings.some((f) => lineNum >= (f.line || 0) && lineNum <= (f.lineEnd || f.line || 0));
                        return (
                          <div key={idx} style={{
                            display: 'flex', fontFamily: 'monospace', fontSize: '11.5px', lineHeight: '1.6',
                            background: isFixed ? 'rgba(79,208,138,0.12)' : 'transparent',
                            borderLeft: isFixed ? '3px solid #4fd08a' : '3px solid transparent',
                          }}>
                            <span style={{
                              width: '36px', flexShrink: 0, textAlign: 'right', padding: '0 8px',
                              color: isFixed ? '#4fd08a' : 'var(--text-faint)', userSelect: 'none', fontSize: '10.5px',
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
                          marginBottom: '12px', border: `1px solid ${meta.border}`,
                          borderRadius: '8px', overflow: 'hidden',
                        }}
                      >
                        {/* Finding header */}
                        <div style={{
                          padding: '10px 12px', background: meta.bg,
                          display: 'flex', alignItems: 'center', gap: '8px',
                        }}>
                          <span style={{
                            fontSize: '10px', fontWeight: 700, padding: '2px 6px', borderRadius: '4px',
                            color: meta.color, background: meta.bg, border: `1px solid ${meta.border}`,
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
                          {finding.vulnerableCode && (
                            <div style={{ marginBottom: '8px' }}>
                              <div style={{ fontSize: '11px', fontWeight: 600, color: '#ff3c5f', marginBottom: '4px' }}>
                                Vulnerable Line(s):
                              </div>
                              <pre style={{
                                margin: 0, padding: '8px', background: 'rgba(255,60,95,0.08)',
                                border: '1px solid rgba(255,60,95,0.2)', borderRadius: '6px',
                                fontSize: '11.5px', lineHeight: '1.5', overflow: 'auto',
                                fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                              }}>
                                {finding.vulnerableCode}
                              </pre>
                            </div>
                          )}
                          {finding.correctedCode && (
                            <div style={{ marginBottom: '8px' }}>
                              <div style={{ fontSize: '11px', fontWeight: 600, color: '#4fd08a', marginBottom: '4px' }}>
                                Secure Fix:
                              </div>
                              <pre style={{
                                margin: 0, padding: '8px', background: 'rgba(79,208,138,0.08)',
                                border: '1px solid rgba(79,208,138,0.2)', borderRadius: '6px',
                                fontSize: '11.5px', lineHeight: '1.5', overflow: 'auto',
                                fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                              }}>
                                {finding.correctedCode}
                              </pre>
                            </div>
                          )}
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
                      width: '100%', padding: '6px 8px', borderRadius: '6px',
                      border: '1px solid rgba(255,255,255,0.1)', background: 'var(--panel)',
                      color: 'var(--text)', fontSize: '12px', marginBottom: '8px',
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

      <PRCreationModal
        isOpen={showPRModal}
        onClose={() => setShowPRModal(false)}
        project={project}
        findings={data?.findings || []}
        filesOriginal={data?.filesOriginal || {}}
        filesCorrected={data?.filesCorrected || {}}
      />
    </div>
  );
}
