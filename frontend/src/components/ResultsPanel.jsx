// ResultsPanel.jsx
// Complete, pixel-perfect Scan Results view matching the reference UI.
// Displays live database-backed scan metrics, side-by-side vulnerable vs corrected code diff,
// line numbers, affected-line highlighting, interactive issue lists, human-level explanations,
// CWE/OWASP references, risk donut chart, metadata panel, and export actions.

import { useState, useEffect, useMemo } from 'react';
import {
  ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2, Info,
  Copy, Download, ArrowRight, Check, Search, ChevronRight,
  ChevronLeft, FileText, Share2, RefreshCw, ExternalLink,
  Code2, Lock, Sliders, Package, Brain, Wrench
} from 'lucide-react';

const SEVERITY_COLORS = {
  Critical: '#ff3c5f',
  High: '#ff8a3d',
  Medium: '#f5b942',
  Low: '#38bdf8',
  Info: '#a78bfa',
};

const SEVERITY_BG = {
  Critical: 'rgba(255, 60, 95, 0.15)',
  High: 'rgba(255, 138, 61, 0.15)',
  Medium: 'rgba(245, 185, 66, 0.15)',
  Low: 'rgba(56, 189, 248, 0.15)',
  Info: 'rgba(167, 139, 250, 0.15)',
};

export default function ResultsPanel({
  scanData,
  onRescan,
  onNavigate,
  scanning = false,
}) {
  const [selectedIssueIndex, setSelectedIssueIndex] = useState(0);
  const [activeTab, setActiveTab] = useState('detected'); // detected | deps | recs | best_practices
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [showLineNumbers, setShowLineNumbers] = useState(true);
  const [highlightIssues, setHighlightIssues] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [copiedVulnerable, setCopiedVulnerable] = useState(false);
  const [copiedSecure, setCopiedSecure] = useState(false);
  const [copiedFix, setCopiedFix] = useState(false);
  const [resolvedMap, setResolvedMap] = useState({});

  const pageSize = 7;

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

    const critical = scanData.criticalCount ?? scanData.critical ?? 0;
    const high = scanData.highCount ?? scanData.highSeverity ?? scanData.high ?? 0;
    const medium = scanData.mediumCount ?? scanData.mediumSeverity ?? scanData.medium ?? 0;
    const low = scanData.lowCount ?? scanData.lowSeverity ?? scanData.low ?? 0;
    const info = scanData.infoCount ?? scanData.info ?? 0;
    const total = scanData.totalFindings ?? findings.length;

    const riskScore = scanData.riskScore ?? 0;
    const securityScore = scanData.securityScore ?? Math.max(0, 100 - riskScore);
    const riskLevel = scanData.riskLevel || (riskScore >= 70 ? 'Critical Risk' : riskScore >= 40 ? 'High Risk' : riskScore >= 15 ? 'Medium Risk' : 'Low Risk');

    return {
      scanUid: scanData.scanUid || `scan_${scanData.id || 'current'}`,
      scannedAt: scanData.scannedAt ? new Date(scanData.scannedAt) : new Date(),
      sourceCode: scanData.sourceCode || '',
      fullCorrectedCode: scanData.fullCorrectedCode || '',
      fileName: scanData.fileName || 'app.py',
      language: scanData.language || 'Python',
      totalLines: scanData.totalLines || (scanData.sourceCode ? scanData.sourceCode.split('\n').length : 0),
      scanMode: scanData.scanMode || 'Deep Scan',
      securityScore,
      riskScore,
      riskLevel,
      totalIssues: total,
      critical,
      high,
      medium,
      low,
      info,
      findings: findings.map((f, i) => ({
        ...f,
        id: f.id || i,
        index: i,
        severity: f.severity || 'Medium',
        line: f.line || 1,
        lineEnd: f.lineEnd || f.line || 1,
      })),
      recommendations: (scanData.recommendations || []).map((r) => {
        if (typeof r === 'string') {
          const category = Object.keys(scanData.byCategory || {}).find((c) => {
            const findings = Array.isArray(scanData.findings) ? scanData.findings : [];
            return findings.some((f) => f.fix === r && (f.category || '') === c);
          }) || 'General';
          return { title: r, severity: 'Medium', desc: r, cwe: category };
        }
        return r;
      }),
      bestPractices: (scanData.bestPractices || []).map((bp) => {
        if (typeof bp === 'string') {
          return { title: bp, status: 'Attention', desc: bp };
        }
        return bp;
      }),
      byCategory: scanData.byCategory || {},
    };
  }, [scanData]);

  // Reset page when filter changes
  useEffect(() => {
    setCurrentPage(1);
    setSelectedIssueIndex(0);
  }, [severityFilter, searchQuery, activeTab]);

  if (!data) {
    return (
      <div className="empty-state" style={{ padding: '60px 20px', textAlign: 'center' }}>
        <FileText size={56} className="empty-icon" style={{ opacity: 0.4, margin: '0 auto 16px' }} />
        <h3 style={{ fontSize: '20px', fontWeight: 600, color: '#f1f5f9' }}>No Scan Results Available</h3>
        <p className="empty-sub" style={{ maxWidth: '440px', margin: '8px auto 20px', color: '#94a3b8' }}>
          Paste your code in the <strong>Code Scan</strong> tab and click <em>Run Security Scan</em> to view real-time findings and code corrections.
        </p>
        <button className="scan-btn" onClick={() => onNavigate && onNavigate('Code Scan')} style={{ margin: '0 auto' }}>
          <Code2 size={16} /> Go to Code Scan
        </button>
      </div>
    );
  }

  // No vulnerabilities detected — show success state
  if (data.findings && data.findings.length === 0) {
    return (
      <div className="scan-results-view">
        <div className="scan-results-header">
          <div>
            <h1 className="scan-results-title">Scan Result</h1>
            <p className="scan-results-subtitle">
              Results for <span className="scan-uid-tag">{data.scanUid}</span>
            </p>
          </div>
          <div className="scan-results-actions">
            <button className="sec-primary-btn" onClick={onRescan} disabled={scanning}>
              <RefreshCw size={14} className={scanning ? 'spin-icon' : ''} /> {scanning ? 'Scanning…' : 'Re-scan Code'}
            </button>
          </div>
        </div>
        <div style={{ padding: '80px 20px', textAlign: 'center' }}>
          <ShieldCheck size={72} color="#4fd08a" style={{ margin: '0 auto 20px' }} />
          <h2 style={{ fontSize: '24px', fontWeight: 700, color: '#f1f5f9', marginBottom: '12px' }}>No Vulnerabilities Detected</h2>
          <p style={{ fontSize: '15px', color: '#94a3b8', maxWidth: '480px', margin: '0 auto 8px' }}>
            Your code passed all <strong>{data.securityScore >= 80 ? '20 security checks' : 'security checks'}</strong> across 20 OWASP Top 10 categories.
          </p>
          <p style={{ fontSize: '14px', color: '#64748b', maxWidth: '480px', margin: '0 auto 24px' }}>
            Security Score: <strong style={{ color: '#4fd08a' }}>{data.securityScore}/100</strong> • Risk Level: <strong style={{ color: '#4fd08a' }}>{data.riskLevel}</strong>
          </p>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
            <button className="scan-btn" onClick={() => onNavigate && onNavigate('Code Scan')} style={{ margin: '0 auto' }}>
              <Code2 size={16} /> Scan More Code
            </button>
          </div>
        </div>
      </div>
    );
  }

  // Filter findings for the list
  const filteredFindings = data.findings.filter((f) => {
    if (activeTab === 'deps' && f.category !== 'Outdated Dependencies' && f.category !== 'Unsafe Dependencies') {
      return false;
    }
    if (activeTab === 'detected' && (f.category === 'Outdated Dependencies' || f.category === 'Unsafe Dependencies')) {
      // Show in deps tab or keep all in detected
    }
    if (severityFilter !== 'all' && (f.severity || '').toLowerCase() !== severityFilter.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        (f.type || '').toLowerCase().includes(q) ||
        (f.category || '').toLowerCase().includes(q) ||
        (f.explanation || '').toLowerCase().includes(q) ||
        (f.cwe || '').toLowerCase().includes(q);
      if (!match) return false;
    }
    return true;
  });

  const totalPages = Math.max(1, Math.ceil(filteredFindings.length / pageSize));
  const paginatedFindings = filteredFindings.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  // Selected issue
  const selectedFinding = filteredFindings[selectedIssueIndex] || filteredFindings[0] || data.findings[0] || null;

  // Build vulnerable lines for the left panel
  const sourceLines = data.sourceCode ? data.sourceCode.split('\n') : [];
  const fullCorrectedLines = data.fullCorrectedCode ? data.fullCorrectedCode.split('\n') : [];

  // Determine affected line numbers for current finding
  const activeLine = selectedFinding ? selectedFinding.line : null;
  const activeLineEnd = selectedFinding ? (selectedFinding.lineEnd || selectedFinding.line) : null;

  // Generate lines for side-by-side viewer
  // Left code: Original submitted source code (or window around vulnerability if code is very large)
  const leftDisplayLines = sourceLines.length > 0 ? sourceLines : (selectedFinding?.vulnerableCode ? selectedFinding.vulnerableCode.split('\n') : ['// No code submitted']);

  // Right code: If fullCorrectedCode exists, use it; otherwise generate a version where the vulnerable line is replaced with the corrected snippet
  let rightDisplayLines = [];
  if (fullCorrectedLines.length > 0 && fullCorrectedLines.length >= sourceLines.length - 2) {
    rightDisplayLines = fullCorrectedLines;
  } else if (selectedFinding && selectedFinding.correctedCode) {
    // Drop in corrected snippet at active line
    const replacement = selectedFinding.correctedCode.split('\n');
    const startIdx = Math.max(0, (selectedFinding.line || 1) - 1);
    const endIdx = Math.max(startIdx, (selectedFinding.lineEnd || selectedFinding.line || 1) - 1);

    const before = sourceLines.slice(0, startIdx);
    const after = sourceLines.slice(endIdx + 1);
    rightDisplayLines = [...before, ...replacement, ...after];
  } else {
    rightDisplayLines = leftDisplayLines;
  }

  // Compute which lines actually differ between vulnerable and fixed code
  // Pad both arrays to the same length so only truly changed lines are highlighted
  const { vulnChangedLines, fixedChangedLines } = useMemo(() => {
    const maxLen = Math.max(leftDisplayLines.length, rightDisplayLines.length);
    const vulnSet = new Set();
    const fixedSet = new Set();
    for (let i = 0; i < maxLen; i++) {
      const left = i < leftDisplayLines.length ? leftDisplayLines[i] : undefined;
      const right = i < rightDisplayLines.length ? rightDisplayLines[i] : undefined;
      // Only mark as changed if both exist and differ, or if one exists and the other is the padding sentinel
      if (left !== undefined && right !== undefined && left !== right) {
        vulnSet.add(i);
        fixedSet.add(i);
      } else if (left !== undefined && right === undefined) {
        // Left has a line that right doesn't — mark left as changed (line removed in fix)
        vulnSet.add(i);
      } else if (left === undefined && right !== undefined) {
        // Right has a line that left doesn't — mark right as changed (line added in fix)
        fixedSet.add(i);
      }
    }
    return { vulnChangedLines: vulnSet, fixedChangedLines: fixedSet };
  }, [leftDisplayLines, rightDisplayLines]);

  // Format date helper
  const formattedDate = data.scannedAt.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  }) + ' at ' + data.scannedAt.toLocaleTimeString('en-US', {
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
  });

  const handleCopyCode = (text, type) => {
    navigator.clipboard.writeText(text);
    if (type === 'vuln') {
      setCopiedVulnerable(true);
      setTimeout(() => setCopiedVulnerable(false), 2000);
    } else if (type === 'secure') {
      setCopiedSecure(true);
      setTimeout(() => setCopiedSecure(false), 2000);
    } else if (type === 'fix') {
      setCopiedFix(true);
      setTimeout(() => setCopiedFix(false), 2000);
    }
  };

  const toggleResolved = (index) => {
    setResolvedMap((prev) => ({
      ...prev,
      [index]: !prev[index],
    }));
  };

  const handleExportJSON = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${data.scanUid}_report.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDownloadPDF = () => {
    window.print();
  };

  // Severity count breakdown for donut chart
  const donutTotal = Math.max(1, data.critical + data.high + data.medium + data.low + data.info);
  const critPct = Math.round((data.critical / donutTotal) * 100);
  const highPct = Math.round((data.high / donutTotal) * 100);
  const medPct = Math.round((data.medium / donutTotal) * 100);
  const lowPct = Math.round((data.low / donutTotal) * 100);

  // Category entries
  const categoryEntries = Object.entries(data.byCategory || {});

  return (
    <div className="scan-results-view">
      {/* Top Header Bar */}
      <div className="scan-results-header">
        <div>
          <h1 className="scan-results-title">Scan Result</h1>
          <p className="scan-results-subtitle">
            Results for <span className="scan-uid-tag">{data.scanUid}</span> • {formattedDate}
          </p>
        </div>
        <div className="scan-results-actions">
          <button className="sec-action-btn" onClick={handleDownloadPDF} title="Download printable report">
            <Download size={14} /> Download Report
          </button>
          <button className="sec-action-btn" onClick={handleExportJSON} title="Export scan data as JSON">
            <Share2 size={14} /> Share
          </button>
          <button className="sec-primary-btn" onClick={onRescan} disabled={scanning}>
            <RefreshCw size={14} className={scanning ? 'spin-icon' : ''} /> {scanning ? 'Scanning…' : 'Re-scan Code'}
          </button>
        </div>
      </div>

      {/* Top Stats Summary Cards Bar (7 Cards) */}
      <div className="scan-stats-row">
        {/* 1. Security Score */}
        <div className="scan-stat-card score-stat-card">
          <div className="score-ring-wrap">
            <svg width="68" height="68" viewBox="0 0 42 42" className="score-ring-svg">
              <circle cx="21" cy="21" r="16" fill="transparent" stroke="#1e2235" strokeWidth="4.5" />
              <circle
                cx="21"
                cy="21"
                r="16"
                fill="transparent"
                stroke={data.securityScore >= 80 ? '#4fd08a' : data.securityScore >= 50 ? '#f5b942' : '#ff3c5f'}
                strokeWidth="4.5"
                strokeDasharray={`${data.securityScore} ${100 - data.securityScore}`}
                strokeDashoffset="25"
                strokeLinecap="round"
              />
              <text x="21" y="20" textAnchor="middle" fontSize="9.5" fill="#f8fafc" fontWeight="700">
                {data.securityScore}
              </text>
              <text x="21" y="27" textAnchor="middle" fontSize="3.8" fill="#94a3b8">
                /100
              </text>
            </svg>
            <div className="score-label-box">
              <div className="stat-label">Security Score</div>
              <div className="risk-badge-text" style={{ color: data.securityScore >= 80 ? '#4fd08a' : data.securityScore >= 50 ? '#f5b942' : '#ff3c5f' }}>
                {data.riskLevel}
              </div>
            </div>
          </div>
        </div>

        {/* 2. Total Issues */}
        <div className="scan-stat-card">
          <div className="stat-label">Total Issues</div>
          <div className="stat-value">{data.totalIssues}</div>
          <div className="stat-sub">Across {Math.max(1, categoryEntries.length)} Categories</div>
        </div>

        {/* 3. Critical */}
        <div className="scan-stat-card sev-crit-card">
          <div className="stat-head-row">
            <span className="stat-dot crit-dot" />
            <span className="stat-label" style={{ color: '#ff3c5f' }}>Critical</span>
          </div>
          <div className="stat-value" style={{ color: '#ff3c5f' }}>{data.critical}</div>
          <div className="stat-sub">High Priority</div>
        </div>

        {/* 4. High */}
        <div className="scan-stat-card sev-high-card">
          <div className="stat-head-row">
            <span className="stat-dot high-dot" />
            <span className="stat-label" style={{ color: '#ff8a3d' }}>High</span>
          </div>
          <div className="stat-value" style={{ color: '#ff8a3d' }}>{data.high}</div>
          <div className="stat-sub">Needs Attention</div>
        </div>

        {/* 5. Medium */}
        <div className="scan-stat-card sev-med-card">
          <div className="stat-head-row">
            <span className="stat-dot med-dot" />
            <span className="stat-label" style={{ color: '#f5b942' }}>Medium</span>
          </div>
          <div className="stat-value" style={{ color: '#f5b942' }}>{data.medium}</div>
          <div className="stat-sub">Potential Risk</div>
        </div>

        {/* 6. Low */}
        <div className="scan-stat-card sev-low-card">
          <div className="stat-head-row">
            <span className="stat-dot low-dot" />
            <span className="stat-label" style={{ color: '#38bdf8' }}>Low</span>
          </div>
          <div className="stat-value" style={{ color: '#38bdf8' }}>{data.low}</div>
          <div className="stat-sub">Minor Issues</div>
        </div>

        {/* 7. Info */}
        <div className="scan-stat-card sev-info-card">
          <div className="stat-head-row">
            <span className="stat-dot info-dot" />
            <span className="stat-label" style={{ color: '#a78bfa' }}>Info</span>
          </div>
          <div className="stat-value" style={{ color: '#a78bfa' }}>{data.info}</div>
          <div className="stat-sub">Informational</div>
        </div>
      </div>

      {/* Main Content Layout: Left Major Column + Right Sidebar Column */}
      <div className="scan-main-grid">
        {/* Left / Center Major Section */}
        <div className="scan-main-left">
          {/* Side-by-Side Dual Code Viewers */}
          <div className="code-comparison-wrapper">
            <div className="code-comparison-grid">
              {/* Left Code Box: Vulnerable Code (Detected) */}
              <div className="code-box vulnerable-box">
                <div className="code-box-header">
                  <div className="code-box-title">
                    <span className="vuln-header-badge">
                      <ShieldAlert size={14} />
                    </span>
                    <span className="code-box-heading" style={{ color: '#ff4d6d' }}>Vulnerable Code</span>
                    <span className="code-box-tag">(Detected)</span>
                  </div>
                  <div className="code-box-meta">
                    <span className="lang-tag">{data.language}</span>
                    <button
                      className="code-copy-btn"
                      onClick={() => handleCopyCode(leftDisplayLines.join('\n'), 'vuln')}
                      title="Copy Vulnerable Code"
                    >
                      {copiedVulnerable ? <Check size={13} color="#4fd08a" /> : <Copy size={13} />}
                    </button>
                  </div>
                </div>

                <div className="code-scroll-area">
                  <table className="code-table">
                    <tbody>
                      {leftDisplayLines.map((lineText, idx) => {
                        const lineNum = idx + 1;
                        const isAffected = highlightIssues && vulnChangedLines.has(idx);
                        return (
                          <tr key={idx} className={`code-row ${isAffected ? 'vuln-row-highlight' : ''}`}>
                            {showLineNumbers && (
                              <td className="code-line-num-cell">
                                <span className="line-num-text">{lineNum}</span>
                                {isAffected && <span className="vuln-indicator-icon">!</span>}
                              </td>
                            )}
                            <td className="code-text-cell">
                              <pre className="code-line-pre">{lineText || ' '}</pre>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Center Transition Arrow */}
              <div className="comparison-arrow-badge">
                <ArrowRight size={18} color="#fff" />
              </div>

              {/* Right Code Box: Fixed & Secure Code (Suggested) */}
              <div className="code-box secure-box">
                <div className="code-box-header">
                  <div className="code-box-title">
                    <span className="secure-header-badge">
                      <CheckCircle2 size={14} />
                    </span>
                    <span className="code-box-heading" style={{ color: '#4fd08a' }}>Fixed & Secure Code</span>
                    <span className="code-box-tag">(Suggested)</span>
                  </div>
                  <div className="code-box-meta">
                    <span className="lang-tag">{data.language}</span>
                    <button
                      className="code-copy-btn"
                      onClick={() => handleCopyCode(rightDisplayLines.join('\n'), 'secure')}
                      title="Copy Fixed Code"
                    >
                      {copiedSecure ? <Check size={13} color="#4fd08a" /> : <Copy size={13} />}
                    </button>
                  </div>
                </div>

                <div className="code-scroll-area">
                  <table className="code-table">
                    <tbody>
                      {rightDisplayLines.map((lineText, idx) => {
                        const lineNum = idx + 1;
                        const isFixedLine = highlightIssues && fixedChangedLines.has(idx);
                        return (
                          <tr key={idx} className={`code-row ${isFixedLine ? 'secure-row-highlight' : ''}`}>
                            {showLineNumbers && (
                              <td className="code-line-num-cell">
                                <span className="line-num-text">{lineNum}</span>
                                {isFixedLine && <span className="secure-indicator-icon">✓</span>}
                              </td>
                            )}
                            <td className="code-text-cell">
                              <pre className="code-line-pre">{lineText || ' '}</pre>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>

            {/* Code Viewer Bottom Toolbar */}
            <div className="code-viewer-toolbar">
              <div className="toolbar-left">
                <span className="toolbar-label">Show:</span>
                <label className="toolbar-checkbox-label">
                  <input
                    type="checkbox"
                    checked={showLineNumbers}
                    onChange={(e) => setShowLineNumbers(e.target.checked)}
                  />
                  <span>Line Numbers</span>
                </label>
                <label className="toolbar-checkbox-label">
                  <input
                    type="checkbox"
                    checked={highlightIssues}
                    onChange={(e) => setHighlightIssues(e.target.checked)}
                  />
                  <span>Highlight Issues</span>
                </label>
              </div>
              <div className="toolbar-right">
                <span className="toolbar-label">Language:</span>
                <span className="lang-badge-pill">{data.language}</span>
              </div>
            </div>
          </div>

          {/* Navigation Tabs (Detected Issues, Dependency Vulns, Security Recs, Best Practices) */}
          <div className="results-tab-bar">
            <button
              className={`results-tab-btn ${activeTab === 'detected' ? 'active' : ''}`}
              onClick={() => setActiveTab('detected')}
            >
              Detected Issues ({data.totalIssues})
            </button>
            <button
              className={`results-tab-btn ${activeTab === 'deps' ? 'active' : ''}`}
              onClick={() => setActiveTab('deps')}
            >
              Dependency Vulnerabilities ({data.findings.filter((f) => (f.category || '').toLowerCase().includes('depend')).length})
            </button>
            <button
              className={`results-tab-btn ${activeTab === 'recs' ? 'active' : ''}`}
              onClick={() => setActiveTab('recs')}
            >
              Security Recommendations ({data.recommendations.length})
            </button>
            <button
              className={`results-tab-btn ${activeTab === 'best_practices' ? 'active' : ''}`}
              onClick={() => setActiveTab('best_practices')}
            >
              Best Practices ({data.bestPractices.length})
            </button>
          </div>

          {/* Tab 1 & 2: Issue Split View (List + Detailed Explanation) */}
          {(activeTab === 'detected' || activeTab === 'deps') && (
            <div className="issues-split-container">
              {/* Left Sub-Column: Issues List */}
              <div className="issues-list-pane">
                <div className="issues-filter-bar">
                  <select
                    className="issues-sev-select"
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                  >
                    <option value="all">All Severity</option>
                    <option value="critical">Critical ({data.critical})</option>
                    <option value="high">High ({data.high})</option>
                    <option value="medium">Medium ({data.medium})</option>
                    <option value="low">Low ({data.low})</option>
                    <option value="info">Info ({data.info})</option>
                  </select>

                  <div className="issues-search-wrap">
                    <Search size={13} className="search-icon-inside" />
                    <input
                      className="issues-search-input"
                      placeholder="Search issues..."
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                    />
                  </div>
                </div>

                <div className="issues-items-list">
                  {paginatedFindings.length === 0 && (
                    <div className="empty-sub" style={{ padding: '30px', textAlign: 'center' }}>
                      No issues matching your filters.
                    </div>
                  )}

                  {paginatedFindings.map((f, i) => {
                    const isSelected = selectedFinding && (selectedFinding.index === f.index || selectedFinding.type === f.type);
                    const isResolved = resolvedMap[f.index];

                    return (
                      <div
                        key={f.index || i}
                        className={`issue-item-row ${isSelected ? 'selected' : ''}`}
                        onClick={() => setSelectedIssueIndex((currentPage - 1) * pageSize + i)}
                      >
                        <div className="issue-item-left">
                          <span
                            className="issue-item-dot"
                            style={{
                              background: SEVERITY_COLORS[f.severity] || '#38bdf8',
                              boxShadow: `0 0 8px ${SEVERITY_COLORS[f.severity] || '#38bdf8'}66`,
                            }}
                          />
                          <div className="issue-item-info">
                            <div className="issue-item-name">{f.type}</div>
                            <div className="issue-item-line">
                              {f.line ? `Line ${f.line}` : f.packageName ? `pkg: ${f.packageName}` : 'Line —'}
                            </div>
                          </div>
                        </div>

                        <div className="issue-item-right">
                          <span
                            className="issue-item-pill"
                            style={{
                              color: SEVERITY_COLORS[f.severity] || '#38bdf8',
                              background: SEVERITY_BG[f.severity] || 'rgba(56,189,248,0.12)',
                              border: `1px solid ${SEVERITY_COLORS[f.severity] || '#38bdf8'}44`,
                            }}
                          >
                            {f.severity}
                          </span>
                          <ChevronRight size={14} className="issue-chevron" />
                        </div>
                      </div>
                    );
                  })}
                </div>

                {filteredFindings.length > pageSize && (
                  <div className="issues-pagination">
                    <span className="pagination-text">
                      Showing {(currentPage - 1) * pageSize + 1} to {Math.min(currentPage * pageSize, filteredFindings.length)} of {filteredFindings.length} issues
                    </span>
                    <div className="pagination-btns">
                      <button
                        className="page-nav-btn"
                        onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                        disabled={currentPage === 1}
                      >
                        <ChevronLeft size={13} />
                      </button>
                      <span className="page-current-num">{currentPage} / {totalPages}</span>
                      <button
                        className="page-nav-btn"
                        onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                        disabled={currentPage === totalPages}
                      >
                        <ChevronRight size={13} />
                      </button>
                    </div>
                  </div>
                )}
              </div>

              {/* Right Sub-Column: Selected Issue Detailed Explanation Card */}
              <div className="issue-detail-pane">
                {selectedFinding ? (
                  <div className="issue-detail-card">
                    {/* Header */}
                    <div className="detail-header-row">
                      <div className="detail-title-group">
                        <span
                          className="detail-icon-circle"
                          style={{ background: SEVERITY_BG[selectedFinding.severity] || 'rgba(255,60,95,0.15)', color: SEVERITY_COLORS[selectedFinding.severity] || '#ff3c5f' }}
                        >
                          <AlertTriangle size={15} />
                        </span>
                        <h2 className="detail-title">{selectedFinding.type}</h2>
                        <span
                          className="detail-sev-pill"
                          style={{
                            color: SEVERITY_COLORS[selectedFinding.severity] || '#ff3c5f',
                            background: SEVERITY_BG[selectedFinding.severity] || 'rgba(255,60,95,0.15)',
                          }}
                        >
                          {selectedFinding.severity}
                        </span>
                        {selectedFinding.cwe && (
                          <span className="detail-cwe-pill">{selectedFinding.cwe.split(':')[0]}</span>
                        )}
                      </div>
                    </div>

                    {/* Metadata Sub-row */}
                    <div className="detail-meta-row">
                      <span><strong>Location:</strong> Line {selectedFinding.line || '1'}{selectedFinding.lineEnd && selectedFinding.lineEnd !== selectedFinding.line ? `-${selectedFinding.lineEnd}` : ''}</span>
                      {selectedFinding.fileName && (
                        <>
                          <span className="meta-sep">•</span>
                          <span><strong>File:</strong> {selectedFinding.fileName}</span>
                        </>
                      )}
                      <span className="meta-sep">•</span>
                      <span><strong>Severity:</strong> <span style={{ color: SEVERITY_COLORS[selectedFinding.severity] || '#ff3c5f' }}>{selectedFinding.severity}</span></span>
                      <span className="meta-sep">•</span>
                      <span><strong>Category:</strong> {selectedFinding.category || 'Vulnerability'}</span>
                    </div>

                    {/* Section 1: What is the problem? */}
                    <div className="detail-section">
                      <div className="detail-section-heading">What is the problem?</div>
                      <p className="detail-section-body">{selectedFinding.explanation}</p>
                    </div>

                    {/* Section 2: Why is it risky? */}
                    <div className="detail-section">
                      <div className="detail-section-heading">Why is it risky?</div>
                      <p className="detail-section-body">{selectedFinding.impact}</p>
                    </div>

                    {/* Section 3: How could an attacker abuse it? */}
                    <div className="detail-section">
                      <div className="detail-section-heading">How could an attacker abuse it?</div>
                      <p className="detail-section-body">{selectedFinding.impact || 'An attacker could exploit this vulnerability to compromise the application security.'}</p>
                    </div>

                    {/* Section 4: How to fix? */}
                    <div className="detail-section">
                      <div className="detail-section-heading">How to fix?</div>
                      <p className="detail-section-body">{selectedFinding.fix}</p>
                    </div>

                    {/* Section 4: References */}
                    <div className="detail-section" style={{ borderBottom: 'none', paddingBottom: 0 }}>
                      <div className="detail-section-heading">References</div>
                      <div className="references-list">
                        {selectedFinding.owasp && (
                          <div className="ref-item">
                            <span className="ref-bullet">OWASP:</span> {selectedFinding.owasp}
                          </div>
                        )}
                        {selectedFinding.cwe && (
                          <div className="ref-item">
                            <span className="ref-bullet">CWE:</span> {selectedFinding.cwe}
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Quick action buttons */}
                    <div className="detail-actions-row">
                      <button
                        className="sec-action-btn"
                        onClick={() => handleCopyCode(selectedFinding.fix || selectedFinding.correctedCode || '', 'fix')}
                      >
                        {copiedFix ? <Check size={14} color="#4fd08a" /> : <Copy size={14} />} {copiedFix ? 'Copied!' : 'Copy Fix'}
                      </button>
                      <button
                        className={`sec-action-btn ${resolvedMap[selectedFinding.index] ? 'resolved-btn' : ''}`}
                        onClick={() => toggleResolved(selectedFinding.index)}
                      >
                        {resolvedMap[selectedFinding.index] ? <CheckCircle2 size={14} color="#4fd08a" /> : <Check size={14} />}
                        {resolvedMap[selectedFinding.index] ? 'Marked as Fixed' : 'Mark as Fixed'}
                      </button>
                    </div>
                  </div>
                ) : (
                  <div className="empty-sub" style={{ padding: '40px', textAlign: 'center' }}>
                    Select an issue from the list to view its remediation details.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Tab 3: Security Recommendations */}
          {activeTab === 'recs' && (
            <div className="tab-content-panel">
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc', marginBottom: '14px' }}>
                Key Security Recommendations
              </h3>
              {data.recommendations.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-faint)' }}>
                  <Wrench size={36} style={{ opacity: 0.3, margin: '0 auto 12px' }} />
                  <p style={{ fontSize: '14px', fontWeight: 500 }}>No security recommendations for this scan.</p>
                  <p style={{ fontSize: '12px', marginTop: '4px' }}>Recommendations are generated from detected findings.</p>
                </div>
              ) : (
                <div className="recs-grid">
                  {data.recommendations.map((rec, i) => (
                    <div className="rec-card" key={i}>
                      <div className="rec-head">
                        <div className="rec-title">{rec.title}</div>
                        <span className="rec-sev-badge" style={{ color: SEVERITY_COLORS[rec.severity] || '#38bdf8' }}>
                          {rec.severity}
                        </span>
                      </div>
                      <div className="rec-desc">{rec.desc}</div>
                      <div className="rec-footer">{rec.cwe}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab 4: Best Practices */}
          {activeTab === 'best_practices' && (
            <div className="tab-content-panel">
              <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#f8fafc', marginBottom: '14px' }}>
                Secure Coding Best Practices
              </h3>
              {data.bestPractices.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-faint)' }}>
                  <CheckCircle2 size={36} style={{ opacity: 0.3, margin: '0 auto 12px' }} />
                  <p style={{ fontSize: '14px', fontWeight: 500 }}>No additional best-practice issues detected.</p>
                  <p style={{ fontSize: '12px', marginTop: '4px' }}>Your code follows recommended security practices.</p>
                </div>
              ) : (
                <div className="bp-list">
                  {data.bestPractices.map((bp, i) => (
                    <div className="bp-card" key={i}>
                      <div className="bp-header">
                        <div className="bp-title">{bp.title}</div>
                        <span className={`bp-status ${bp.status === 'Passing' ? 'passing' : 'attention'}`}>
                          {bp.status}
                        </span>
                      </div>
                      <p className="bp-desc">{bp.desc}</p>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Sidebar Column (Scan Metadata, Risk Overview, Top Categories, Actions) */}
        <div className="scan-main-right">
          {/* 1. Scan Metadata Card */}
          <div className="sidebar-card">
            <div className="sidebar-card-title">Scan Metadata</div>
            <div className="meta-list">
              <div className="meta-item">
                <span className="meta-key">Scan ID</span>
                <span className="meta-val font-mono">{data.scanUid}</span>
              </div>
              <div className="meta-item">
                <span className="meta-key">Project</span>
                <span className="meta-val">SecureCode-App</span>
              </div>
              <div className="meta-item">
                <span className="meta-key">File Name</span>
                <span className="meta-val font-mono">{data.fileName}</span>
              </div>
              <div className="meta-item">
                <span className="meta-key">Language</span>
                <span className="meta-val">{data.language}</span>
              </div>
              <div className="meta-item">
                <span className="meta-key">Scan Time</span>
                <span className="meta-val">{formattedDate}</span>
              </div>
              <div className="meta-item">
                <span className="meta-key">Lines of Code</span>
                <span className="meta-val font-mono">{data.totalLines}</span>
              </div>
              <div className="meta-item">
                <span className="meta-key">Scan Mode</span>
                <span className="meta-val">{data.scanMode}</span>
              </div>
            </div>
          </div>

          {/* 2. Risk Overview Donut Card */}
          <div className="sidebar-card">
            <div className="sidebar-card-title">Risk Overview</div>
            <div className="risk-donut-container">
              <div className="donut-chart-wrap">
                <svg width="100" height="100" viewBox="0 0 42 42" className="risk-donut-svg">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#1e2235" strokeWidth="5.5" />
                  {(() => {
                    let offset = 25;
                    const slices = [
                      { count: data.critical, pct: critPct, color: '#ff3c5f' },
                      { count: data.high, pct: highPct, color: '#ff8a3d' },
                      { count: data.medium, pct: medPct, color: '#f5b942' },
                      { count: data.low, pct: lowPct, color: '#38bdf8' },
                    ];
                    return slices.map((s, i) => {
                      if (s.pct <= 0) return null;
                      const elem = (
                        <circle
                          key={i}
                          cx="21"
                          cy="21"
                          r="15.9"
                          fill="transparent"
                          stroke={s.color}
                          strokeWidth="5.5"
                          strokeDasharray={`${s.pct} ${100 - s.pct}`}
                          strokeDashoffset={offset}
                        />
                      );
                      offset -= s.pct;
                      return elem;
                    });
                  })()}
                </svg>
              </div>
              <div className="donut-legend">
                <div className="legend-item">
                  <span className="legend-dot" style={{ background: '#ff3c5f' }} />
                  <span className="legend-name">Critical</span>
                  <span className="legend-count">{data.critical} ({critPct}%)</span>
                </div>
                <div className="legend-item">
                  <span className="legend-dot" style={{ background: '#ff8a3d' }} />
                  <span className="legend-name">High</span>
                  <span className="legend-count">{data.high} ({highPct}%)</span>
                </div>
                <div className="legend-item">
                  <span className="legend-dot" style={{ background: '#f5b942' }} />
                  <span className="legend-name">Medium</span>
                  <span className="legend-count">{data.medium} ({medPct}%)</span>
                </div>
                <div className="legend-item">
                  <span className="legend-dot" style={{ background: '#38bdf8' }} />
                  <span className="legend-name">Low</span>
                  <span className="legend-count">{data.low} ({lowPct}%)</span>
                </div>
              </div>
            </div>
          </div>

          {/* 3. Top Issue Categories Card */}
          <div className="sidebar-card">
            <div className="sidebar-card-title">Top Issue Categories</div>
            <div className="categories-list">
              {categoryEntries.length === 0 && (
                <div className="empty-sub" style={{ padding: '10px' }}>No categories found</div>
              )}
              {categoryEntries.map(([cat, count], idx) => {
                const iconColor =
                  idx % 4 === 0 ? '#ff3c5f' : idx % 4 === 1 ? '#ff8a3d' : idx % 4 === 2 ? '#f5b942' : '#38bdf8';
                return (
                  <div className="category-row" key={cat}>
                    <div className="category-left">
                      <span className="cat-icon-dot" style={{ color: iconColor }}>
                        <ShieldAlert size={13} />
                      </span>
                      <span className="cat-name">{cat}</span>
                    </div>
                    <span className="cat-count-badge">{count}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 4. Scan Actions Card */}
          <div className="sidebar-card">
            <div className="sidebar-card-title">Scan Actions</div>
            <div className="action-buttons-list">
              <button className="scan-sidebar-btn" onClick={handleDownloadPDF}>
                <FileText size={14} /> Download PDF Report
              </button>
              <button className="scan-sidebar-btn" onClick={handleExportJSON}>
                <Download size={14} /> Export as JSON
              </button>
              <button
                className="scan-sidebar-btn"
                onClick={() => onNavigate && onNavigate('Code Scan')}
              >
                <ExternalLink size={14} /> View in Code Scan
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}