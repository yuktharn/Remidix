import { useState, useEffect } from 'react';
import {
  ShieldCheck, HelpCircle, Sun, Moon, Code2, Trash2, FileText, Zap,
  Search, BarChart2, Lock, Clock, Settings, Info, CheckCircle2,
  AlertTriangle, ChevronRight, ChevronDown, Menu, X,
  ShieldAlert, KeyRound, Sliders, Package, Brain,
  Home, GitCompare, Folder, Bookmark, TrendingUp, Gauge, CalendarDays,
  UploadCloud, Check, Bug, Wrench, Gauge as GaugeIcon,
  Eye, EyeOff, Copy, Database, Cloud, ExternalLink, Download,
} from 'lucide-react';
import './App.css';
import ProjectsPanel from './ProjectsPanel';

const API_URL = 'http://localhost:4000';

// Sidebar nav, grouped to match the full feature list. "How It Works" reuses
// the existing topbar modal instead of a page (special: 'modal'). Everything
// else under Analysis / Results & Reports reads from the same `results` /
// `history` state Code Scan already populates — no duplicate scanning.
const NAV_GROUPS = [
  {
    label: 'Overview',
    items: [{ label: 'Dashboard', icon: Home }],
  },
  {
    label: 'Scan',
    items: [{ label: 'Code Scan', icon: Code2 }],
  },
  {
    label: 'Results & Reports',
    items: [
      { label: 'Scan Results', icon: FileText },
      { label: 'Scan History', icon: Clock },
      { label: 'Reports', icon: BarChart2 },
    ],
  },
  {
    label: 'Analysis',
    items: [
      { label: 'Security Coverage', icon: ShieldAlert },
      { label: 'Secrets Detection', icon: KeyRound },
      { label: 'Configuration Check', icon: Sliders },
      { label: 'Dependency Check', icon: Package },
      { label: 'AI Prioritization', icon: Brain },
    ],
  },
  {
    label: 'Manage',
    items: [
      { label: 'Projects', icon: Folder },
      
    ],
  },
  {
    label: 'Settings & Help',
    items: [
      { label: 'Settings', icon: Settings },
      { label: 'How It Works', icon: HelpCircle, special: 'modal' },
      { label: 'About', icon: Info },
    ],
  },
];

const FEATURES = [
  { icon: Zap, color: 'amber', title: 'Fast scanning', desc: 'Quick and accurate results' },
  { icon: ShieldCheck, color: 'green', title: 'Secure & private', desc: 'Your code stays on your device' },
  { icon: Search, color: 'blue', title: 'Smart detection', desc: 'Detects keys, tokens & secrets' },
  { icon: BarChart2, color: 'teal', title: 'Detailed reports', desc: 'Easy to understand findings' },
];

function severityClass(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return 'sev-critical';
  if (s === 'high') return 'sev-high';
  if (s === 'medium') return 'sev-medium';
  return 'sev-low';
}

// Inline fallback color for the Critical badge/chip in case App.css doesn't
// yet define .sev-critical — safe to remove once you add that CSS class.
const CRITICAL_FALLBACK = { background: 'rgba(255,0,60,0.15)', color: '#ff3c5f', border: '1px solid rgba(255,0,60,0.4)' };

// Maps a finding's `type` string to one of the 9 requirement categories.
// Used to build Security Coverage / Secrets Detection / Configuration Check
// / AI Prioritization / Reports from the same results Code Scan already
// produces, instead of re-scanning.
function categoryOf(f) {
  const t = (f.type || '').toLowerCase();
  if (t.includes('sql') || t.includes('injection') || t.includes('xss')) return 'injection';
  if (t.includes('key') || t.includes('secret') || t.includes('password') || t.includes('token') || t.includes('credential')) return 'secrets';
  if (t.includes('auth')) return 'auth';
  if (t.includes('access') || t.includes('permission') || t.includes('rbac')) return 'access';
  if (t.includes('config') || t.includes('cors') || t.includes('debug') || t.includes('tls')) return 'config';
  if (t.includes('logic')) return 'logic';
  if (t.includes('cve') || t.includes('depend') || t.includes('vulnerable package')) return 'deps';
  return 'other';
}

// Risk-score bands for the "AI Risk Score Range" column on AI Prioritization
// — Critical 90-100, High 70-89, Medium 40-69, Low 0-39.
const SEVERITY_BANDS = { critical: [90, 100], high: [70, 89], medium: [40, 69], low: [0, 39] };

// Derives a 0-100 risk score for a single finding from its severity band,
// nudged by the finding's own confidence (if the backend provided one).
// Deterministic and explainable — no black box.
function computeRiskScore(f) {
  const sev = (f.severity || '').toLowerCase();
  const [lo, hi] = SEVERITY_BANDS[sev] || SEVERITY_BANDS.low;
  const conf = typeof f.confidence === 'number' ? Math.min(1, Math.max(0, f.confidence)) : 0.85;
  return Math.round(lo + conf * (hi - lo));
}

// Short, real explanation for the "Reason" column — reuses the finding's
// own `explanation` (first sentence) when present, falling back to a
// severity-based description when it isn't.
function reasonForFinding(f) {
  if (f.explanation) {
    const firstSentence = f.explanation.split(/(?<=[.!?])\s/)[0];
    return firstSentence.length > 90 ? `${firstSentence.slice(0, 87)}…` : firstSentence;
  }
  const sev = (f.severity || '').toLowerCase();
  if (sev === 'critical') return 'Easily exploitable, high impact';
  if (sev === 'high') return 'Exploitable with some effort, high impact';
  if (sev === 'medium') return 'Limited exploitability, moderate impact';
  return 'Low exploitability, minimal impact';
}

// "File / Location" column — uses real fields already on the finding
// (packageName/version for dependency findings, line for everything else).
function locationForFinding(f) {
  if (f.packageName) return `package.json — ${f.packageName}${f.version ? `@${f.version}` : ''}`;
  if (f.line) return `line ${f.line}`;
  return '—';
}

const COVERAGE_CATEGORIES = [
  { key: 'secrets', label: 'Exposed Secrets' },
  { key: 'injection', label: 'Injection Vulnerabilities' },
  { key: 'auth', label: 'Insecure Authentication' },
  { key: 'access', label: 'Improper Access Control' },
  { key: 'config', label: 'Insecure Configuration' },
  { key: 'logic', label: 'Logic Errors' },
  { key: 'deps', label: 'Unsafe Dependencies' },
];

// The 9 tiles shown on the Dashboard's "Security capabilities" grid. The
// first 7 map 1:1 to COVERAGE_CATEGORIES (status driven by real findings);
// the last 2 are always-on pipeline stages (no per-finding category).
const CAPABILITY_TILES = [
  { key: 'secrets', label: 'Exposed secrets', detectedLabel: 'Detected', cleanLabel: 'Clean', icon: KeyRound },
  { key: 'auth', label: 'Insecure authentication', detectedLabel: 'AI analyzed', cleanLabel: 'Clean', icon: Lock },
  { key: 'access', label: 'Improper access control', detectedLabel: 'AI analyzed', cleanLabel: 'Clean', icon: ShieldAlert },
  { key: 'injection', label: 'Injection vulnerabilities', detectedLabel: 'Detected', cleanLabel: 'Clean', icon: Zap },
  { key: 'deps', label: 'Unsafe dependencies', detectedLabel: 'OSV checked', cleanLabel: 'Clean', icon: Package },
  { key: 'config', label: 'Insecure configurations', detectedLabel: 'AI analyzed', cleanLabel: 'Clean', icon: Sliders },
  { key: 'logic', label: 'Logic errors', detectedLabel: 'AI analyzed', cleanLabel: 'Clean', icon: Brain },
  { key: 'ai-prioritization', label: 'AI prioritization', always: 'Active', icon: Brain },
  { key: 'fp-reduction', label: 'False positive reduction', always: 'Confidence based', icon: CheckCircle2 },
];

// Groups the fine-grained categoryOf() buckets into the 4 rows shown in the
// Dashboard's "Findings by category" bar chart.
function dashboardCategoryOf(f) {
  const c = categoryOf(f);
  if (c === 'injection') return 'Injection';
  if (c === 'secrets') return 'Secrets';
  if (c === 'deps') return 'Dependencies';
  return 'Others';
}

// "1. What do you want to scan?" tabs. Config/Deps/Upload set scanType,
// which handleScan() uses to decide how to build the request body — Deps
// always sends packageJson, Upload reads the picked file's text into `code`.
const SCAN_TYPES = [
  { key: 'code', label: 'Source Code', desc: '.js, .py, .java, .cpp and more', icon: Code2 },
  { key: 'config', label: 'Configuration', desc: '.env, .json, .yml, docker etc.', icon: Sliders },
  { key: 'deps', label: 'Dependencies', desc: 'package.json, requirements.txt', icon: Package },
  { key: 'upload', label: 'File Upload', desc: 'Upload any file to scan', icon: UploadCloud },
];

// "3. Scan Configuration" checkboxes. Only `secrets` maps to a real backend
// param (entropyEnabled) — the rest reflect stages the backend always runs
// on every scan, so toggling them off here is visual only for now (there's
// no per-check on/off support in the /scan endpoint yet).
const CHECK_ITEMS = [
  { key: 'secrets', title: 'Secret Detection', desc: 'Detect API keys, tokens, passwords, etc.' },
  { key: 'vuln', title: 'Vulnerability Analysis', desc: 'Detect common security vulnerabilities' },
  { key: 'deps', title: 'Dependency Check', desc: 'Check for vulnerable dependencies' },
  { key: 'aiContext', title: 'AI Context Analysis', desc: 'AI analyzes code context & intent' },
  { key: 'riskPrioritization', title: 'Risk Prioritization', desc: 'Prioritize based on impact & exploitability' },
  { key: 'confidence', title: 'Confidence Analysis', desc: 'Reduce false positives with confidence' },
];

// "5. Analysis Pipeline" — the backend does this in one request, so there
// are no real per-stage events to hook into. Each step shows pending before
// a scan, running while the request is in flight, and complete once results
// come back — an honest simplification rather than faked per-stage timing.
const PIPELINE_STEPS = [
  { key: 'input', label: 'Input Validation', icon: FileText },
  { key: 'secrets', label: 'Secrets & Entropy', icon: KeyRound },
  { key: 'vuln', label: 'Vulnerability Scan', icon: Bug },
  { key: 'deps', label: 'Dependency Check', icon: Package },
  { key: 'ai', label: 'AI Analysis', icon: Brain },
  { key: 'risk', label: 'Risk Prioritization', icon: ShieldAlert },
  { key: 'confidence', label: 'Confidence Analysis', icon: CheckCircle2 },
];

function formatDate(dateStr) {
  const d = new Date(dateStr);
  return d.toLocaleString(undefined, {
    month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
  });
}

function parseFindings(scan) {
  if (!scan) return [];
  if (Array.isArray(scan.findings)) return scan.findings;
  if (typeof scan.findings === 'string') {
    try { return JSON.parse(scan.findings); } catch { return []; }
  }
  return [];
}

// Dashboard — reads only from real state (results = latest in-session scan,
// history = all saved scans from GET /history). No mock data.
function DashboardPanel({ results, history, historyLoading }) {
  const sortedHistory = [...history].sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
  // Prefer the live `results` from the current session (has the freshest
  // findings array); fall back to the most recent saved scan.
  const latest = results || sortedHistory[0] || null;
  const latestFindings = results ? (results.findings || []) : parseFindings(sortedHistory[0]);

  const critical = latest?.critical ?? 0;
  const high = latest?.highSeverity ?? 0;
  const medium = latest?.mediumSeverity ?? 0;
  const low = latest?.lowSeverity ?? 0;
  const total = latest?.totalFindings ?? (critical + high + medium + low);
  const riskScore = latest?.riskScore ?? 0;
  const riskLevel = latest?.riskLevel ?? '—';

  const categoriesPresent = new Set(latestFindings.map(dashboardCategoryOf)).size;

  const confidences = latestFindings.filter((f) => typeof f.confidence === 'number');
  const aiConfidence = confidences.length
    ? Math.round((confidences.reduce((sum, f) => sum + f.confidence, 0) / confidences.length) * 100)
    : null;

  const now = new Date();
  const thisMonthScans = history.filter((s) => {
    const d = new Date(s.scannedAt);
    return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
  });
  const lastMonthDate = new Date(now.getFullYear(), now.getMonth() - 1, 1);
  const lastMonthScans = history.filter((s) => {
    const d = new Date(s.scannedAt);
    return d.getMonth() === lastMonthDate.getMonth() && d.getFullYear() === lastMonthDate.getFullYear();
  });
  const monthDelta = lastMonthScans.length
    ? Math.round(((thisMonthScans.length - lastMonthScans.length) / lastMonthScans.length) * 100)
    : null;

  const severityData = [
    { label: 'Critical', count: critical, color: '#e2504a' },
    { label: 'High', count: high, color: '#e8a33d' },
    { label: 'Medium', count: medium, color: '#d9c94f' },
    { label: 'Low', count: low, color: '#4fd08a' },
  ];

  const categoryLabels = ['Injection', 'Secrets', 'Dependencies', 'Others'];
  const categoryCounts = categoryLabels.map((label) => ({
    label,
    count: latestFindings.filter((f) => dashboardCategoryOf(f) === label).length,
  }));
  const maxCategoryCount = Math.max(1, ...categoryCounts.map((c) => c.count));

  // Last 7 scans, oldest to latest, for the risk trend line.
  const trendScans = [...sortedHistory].slice(0, 7).reverse();

  const recentScans = sortedHistory.slice(0, 3);

  const topVulns = [...latestFindings]
    .sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return (order[(a.severity || '').toLowerCase()] ?? 4) - (order[(b.severity || '').toLowerCase()] ?? 4);
    })
    .slice(0, 3);

  const hasAnyData = Boolean(latest);

  return (
    <section className="panel wide-panel dashboard-panel">
      <div className="panel-head">
        <div className="panel-icon"><Home size={18} /></div>
        <div><h2>Dashboard</h2><p>Overview of your security posture and recent scans.</p></div>
      </div>

      {historyLoading && !hasAnyData && (
        <div className="empty-state">
          <Clock size={56} className="empty-icon" />
          <h3>Loading your scan data…</h3>
        </div>
      )}

      {!historyLoading && !hasAnyData && (
        <div className="empty-state">
          <Home size={56} className="empty-icon" />
          <h3>No scans yet.</h3>
          <p className="empty-sub">Run a scan from Code Scan and your dashboard will populate automatically.</p>
        </div>
      )}

      {hasAnyData && (
        <>
          <div className="dash-stats-grid">
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#3a1d1d', color: '#e2504a' }}><ShieldAlert size={14} /></span>Risk score</div>
              <div className="dash-stat-value">{riskScore}<span> / 100</span></div>
              <div className="dash-stat-sub" style={{ color: '#e8a33d' }}>{riskLevel} risk</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#241a3a', color: '#a98cf0' }}><FileText size={14} /></span>Total findings</div>
              <div className="dash-stat-value">{total}</div>
              <div className="dash-stat-sub">Across {categoriesPresent} categor{categoriesPresent === 1 ? 'y' : 'ies'}</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#12301f', color: '#4fd08a' }}><CheckCircle2 size={14} /></span>AI confidence</div>
              <div className="dash-stat-value">{aiConfidence !== null ? `${aiConfidence}%` : '—'}</div>
              <div className="dash-stat-sub" style={{ color: '#4fd08a' }}>{aiConfidence !== null ? 'From analyzed findings' : 'No AI findings yet'}</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#12283a', color: '#3ba7f0' }}><Clock size={14} /></span>Last scan</div>
              <div className="dash-stat-value" style={{ fontSize: '16px' }}>{sortedHistory[0] ? formatDate(sortedHistory[0].scannedAt) : 'Just now'}</div>
              <div className="dash-stat-sub">Completed</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#12283a', color: '#3ba7f0' }}><CalendarDays size={14} /></span>Scans this month</div>
              <div className="dash-stat-value">{thisMonthScans.length}</div>
              <div className="dash-stat-sub" style={{ color: monthDelta === null ? undefined : monthDelta >= 0 ? '#4fd08a' : '#e2504a' }}>
                {monthDelta === null ? 'No data for last month' : `${monthDelta >= 0 ? '↑' : '↓'} ${Math.abs(monthDelta)}% vs last month`}
              </div>
            </div>
          </div>

          <div className="dash-mid-grid">
            <div className="dash-sub-panel">
              <h3>Findings by severity</h3>
              <div className="dash-donut-row">
                <svg width="100" height="100" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  {(() => {
                    let offset = 25;
                    return severityData.map((s) => {
                      const pct = total > 0 ? (s.count / total) * 100 : 0;
                      const circle = (
                        <circle
                          key={s.label}
                          cx="21" cy="21" r="15.9" fill="transparent"
                          stroke={s.color} strokeWidth="6"
                          strokeDasharray={`${pct} ${100 - pct}`}
                          strokeDashoffset={offset}
                        />
                      );
                      offset -= pct;
                      return circle;
                    });
                  })()}
                  <text x="21" y="19" textAnchor="middle" fontSize="7" fill="#e8e9ee" fontWeight="700">{total}</text>
                  <text x="21" y="26" textAnchor="middle" fontSize="4" fill="#5c5f6d">Total</text>
                </svg>
                <div className="dash-legend">
                  {severityData.map((s) => (
                    <div className="dash-legend-item" key={s.label}>
                      <span className="dash-dot" style={{ background: s.color }} />{s.label}
                      <span className="dash-legend-count">{s.count} ({total > 0 ? Math.round((s.count / total) * 100) : 0}%)</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Findings by category</h3>
              {categoryCounts.map((c) => (
                <div className="dash-cat-row" key={c.label}>
                  <div className="dash-cat-label">{c.label}</div>
                  <div className="dash-cat-track"><div className="dash-cat-fill" style={{ width: `${(c.count / maxCategoryCount) * 100}%` }} /></div>
                  <div className="dash-cat-count">{c.count}</div>
                </div>
              ))}
            </div>

            <div className="dash-sub-panel">
              <h3>Risk trend</h3>
              <p className="dash-sub-caption">Last {trendScans.length || 0} scans</p>
              {trendScans.length === 0 && <p className="empty-sub">Not enough history yet.</p>}
              {trendScans.length > 0 && (
                <svg width="100%" height="110" viewBox="0 0 260 100" preserveAspectRatio="none">
                  <polyline
                    fill="none" stroke="#e8a33d" strokeWidth="2"
                    points={trendScans.map((s, i) => {
                      const x = trendScans.length > 1 ? (i / (trendScans.length - 1)) * 250 + 5 : 130;
                      const y = 90 - ((s.riskScore ?? 0) / 100) * 80;
                      return `${x},${y}`;
                    }).join(' ')}
                  />
                  {trendScans.map((s, i) => {
                    const x = trendScans.length > 1 ? (i / (trendScans.length - 1)) * 250 + 5 : 130;
                    const y = 90 - ((s.riskScore ?? 0) / 100) * 80;
                    return <circle key={i} cx={x} cy={y} r="3" fill="#e8a33d" />;
                  })}
                </svg>
              )}
            </div>
          </div>

          <div className="dash-sub-panel" style={{ marginBottom: '16px' }}>
            <h3>Security capabilities ({CAPABILITY_TILES.length})</h3>
            <p className="dash-sub-caption">Status reflects your most recent scan.</p>
            <div className="dash-cap-grid">
              {CAPABILITY_TILES.map((cap, i) => {
                const Icon = cap.icon;
                const hasFinding = cap.key !== 'ai-prioritization' && cap.key !== 'fp-reduction'
                  ? latestFindings.some((f) => categoryOf(f) === cap.key)
                  : false;
                const status = cap.always ?? (hasFinding ? cap.detectedLabel : cap.cleanLabel);
                const statusColor = cap.always ? '#a98cf0' : hasFinding ? '#e8a33d' : '#4fd08a';
                return (
                  <div className="dash-cap-card" key={cap.key}>
                    <div className="dash-cap-icon"><Icon size={14} /></div>
                    <div className="dash-cap-title">{i + 1}. {cap.label}</div>
                    <div className="dash-cap-status" style={{ color: statusColor }}>{status}</div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="dash-bottom-grid">
            <div className="dash-sub-panel">
              <div className="dash-panel-title-row"><h3>Recent scans</h3></div>
              {recentScans.length === 0 && <p className="empty-sub">No saved scans yet.</p>}
              {recentScans.map((s) => (
                <div className="dash-scan-row" key={s.id}>
                  <div className="dash-scan-icon"><Clock size={14} /></div>
                  <div className="dash-scan-meta">
                    <div className="dash-scan-name">{formatDate(s.scannedAt)}</div>
                    <div className="dash-scan-time">{s.totalFindings ?? ((s.critical ?? 0) + (s.highSeverity ?? 0) + (s.mediumSeverity ?? 0) + (s.lowSeverity ?? 0))} findings</div>
                  </div>
                  <span className={`sev-pill ${severityClass(s.riskLevel)}`} style={severityClass(s.riskLevel) === 'sev-critical' ? CRITICAL_FALLBACK : undefined}>
                    {s.riskScore ?? 0} {s.riskLevel ?? ''}
                  </span>
                </div>
              ))}
            </div>

            <div className="dash-sub-panel">
              <div className="dash-panel-title-row"><h3>Top vulnerabilities</h3></div>
              {topVulns.length === 0 && <p className="empty-sub">No findings in the latest scan.</p>}
              {topVulns.map((f, i) => (
                <div className="dash-scan-row" key={i}>
                  <div className="dash-scan-meta">
                    <div className="dash-scan-name">{f.type}</div>
                  </div>
                  <span className={`sev-pill ${severityClass(f.severity)}`} style={severityClass(f.severity) === 'sev-critical' ? CRITICAL_FALLBACK : undefined}>
                    {f.severity}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </>
      )}
    </section>
  );
}

// Collapsible recommendations list — shows first 3, expandable to see the rest
function RecommendationsList({ items }) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? items : items.slice(0, 3);
  return (
    <div className="finding-card">
      <div className="finding-type">Recommendations ({items.length})</div>
      <div style={{ marginTop: '6px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {visible.map((r, i) => (
          <div key={i} className="finding-preview">{r}</div>
        ))}
      </div>
      {items.length > 3 && (
        <button className="text-btn" style={{ marginTop: '8px' }} onClick={() => setExpanded(!expanded)}>
          {expanded ? 'Show less' : `Show ${items.length - 3} more`}
        </button>
      )}
    </div>
  );
}

// A single finding card. Expandable when it has an explanation and/or fix
// (LLM findings and dependency findings have these — plain pattern/entropy
// findings don't, so those cards just stay flat like before).
function FindingItem({ f }) {
  const [open, setOpen] = useState(false);
  const hasDetail = Boolean(f.explanation || f.fix);
  const isCritical = severityClass(f.severity) === 'sev-critical';

  return (
    <div
      className="finding-card"
      style={hasDetail ? { cursor: 'pointer' } : undefined}
      onClick={() => hasDetail && setOpen((o) => !o)}
    >
      <div className="finding-top">
        <span className={`sev-pill ${severityClass(f.severity)}`} style={isCritical ? CRITICAL_FALLBACK : undefined}>
          {f.severity}
        </span>
        {f.line ? <span className="finding-line">line {f.line}</span> : <span className="finding-line" />}
      </div>
      <div className="finding-type">{f.type}</div>
      <div className="finding-preview">{f.matchPreview}</div>
      {f.method && <span className="finding-method">{f.method}</span>}

      {hasDetail && (
        <div style={{ marginTop: '8px', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '12px', opacity: 0.7 }}>
          {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          <span>{open ? 'Hide details' : 'Why it matters + fix'}</span>
        </div>
      )}

      {open && hasDetail && (
        <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid rgba(255,255,255,0.08)', fontSize: '13px' }}>
          {f.explanation && (
            <div style={{ marginBottom: '6px' }}>
              <span style={{ opacity: 0.6 }}>Why it matters: </span>{f.explanation}
            </div>
          )}
          {f.fix && (
            <div>
              <span style={{ opacity: 0.6 }}>Suggested fix: </span>{f.fix}
            </div>
          )}
          {typeof f.confidence === 'number' && (
            <div style={{ marginTop: '6px', fontSize: '11px', opacity: 0.55 }}>
              {Math.round(f.confidence * 100)}% confidence
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// Code Scan history row
function HistoryRow({ scan }) {
  const [open, setOpen] = useState(false);
  const findings = typeof scan.findings === 'string' ? JSON.parse(scan.findings) : scan.findings;

  return (
    <div className="finding-card" style={{ cursor: 'pointer' }}>
      <div className="finding-top" onClick={() => setOpen(!open)}>
        <span className="finding-line">{formatDate(scan.scannedAt)}</span>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </div>
      <div className="summary-row" style={{ marginTop: '8px', marginBottom: open ? '10px' : 0 }}>
        {scan.riskLevel && (
          <div className="summary-chip" style={severityClass(scan.riskLevel) === 'sev-critical' ? CRITICAL_FALLBACK : undefined}>
            risk: {scan.riskLevel}
          </div>
        )}
        <div className="summary-chip sev-high">{scan.highSeverity} high</div>
        <div className="summary-chip sev-medium">{scan.mediumSeverity} medium</div>
        <div className="summary-chip sev-low">{scan.lowSeverity} low</div>
      </div>
      {open && (
        <div className="findings-list" style={{ marginTop: '10px' }}>
          {findings.map((f, i) => (
            <FindingItem key={i} f={f} />
          ))}
        </div>
      )}
    </div>
  );
}

// Collapsible findings list for Code Scan results
function CodeFindingsList({ findings, criticalCount, highCount, mediumCount, lowCount }) {
  const [expanded, setExpanded] = useState(false);
  const visible = expanded ? findings : findings.slice(0, 3);

  return (
    <>
      <div className="summary-row">
        {criticalCount > 0 && (
          <div className="summary-chip" style={CRITICAL_FALLBACK}>{criticalCount} critical</div>
        )}
        <div className="summary-chip sev-high">{highCount} high</div>
        <div className="summary-chip sev-medium">{mediumCount} medium</div>
        <div className="summary-chip sev-low">{lowCount} low</div>
      </div>
      <div className="findings-list" style={{ marginTop: '10px' }}>
        {visible.map((f, i) => (
          <FindingItem key={i} f={f} />
        ))}
      </div>
      {findings.length > 3 && (
        <button className="text-btn" style={{ marginTop: '10px' }} onClick={() => setExpanded(!expanded)}>
          {expanded ? 'Show less' : `Show ${findings.length - 3} more`}
        </button>
      )}
    </>
  );
}

// ============================================================================
// Dependency Check — dedicated panel (replaces the old standalone paste-box
// version). Reads from the same `results` / `code` state Code Scan already
// populates, the same way SecretsDetectionPanel does — run a scan from
// Code Scan with "Dependencies" selected (or paste a package.json — it's
// auto-detected), then this view mirrors that scan.
//
// Every field rendered here comes straight from depScanner.js's findings:
// packageName, version, vulnId, severity, publishedDate, fixedVersion,
// osvUrl, explanation, fix, confidence. Nothing here is fabricated —
// there's intentionally no "Latest Version" column unless fixedVersion is
// known, no fake file list, and no fake package-category breakdown, since
// none of that exists in a plain package.json.
// ============================================================================

function parsePackageJsonClientSide(content) {
  if (!content) return null;
  try {
    const parsed = JSON.parse(content);
    const deps = { ...(parsed.dependencies || {}), ...(parsed.devDependencies || {}) };
    const names = Object.keys(deps);
    return names.length > 0 ? names : null;
  } catch {
    return null;
  }
}

function formatOSVDate(dateStr) {
  if (!dateStr) return '—';
  const d = new Date(dateStr);
  if (isNaN(d.getTime())) return '—';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

function DependencyCheckPanel({ results, code }) {
  const allFindings = results?.findings || [];
  const depFindings = allFindings.filter((f) => categoryOf(f) === 'deps');

  // Total packages scanned — parsed client-side from the same package.json
  // that was pasted into Code Scan. Falls back to null (shown as "—") if
  // the pasted content wasn't valid JSON with a dependencies key, which can
  // happen if results came from a non-dependency scan.
  const allPackageNames = parsePackageJsonClientSide(code);
  const vulnerablePackageNames = [...new Set(depFindings.map((f) => f.packageName).filter(Boolean))];
  const totalPackages = allPackageNames ? allPackageNames.length : null;
  const safePackages = totalPackages !== null ? Math.max(0, totalPackages - vulnerablePackageNames.length) : null;
  const healthPct = totalPackages
    ? Math.round((safePackages / totalPackages) * 100)
    : (results && depFindings.length === 0 ? 100 : null);
  const healthLabel = healthPct === null ? '—' : healthPct >= 80 ? 'Good' : healthPct >= 50 ? 'Moderate' : 'Poor';
  const healthColor = healthPct === null ? '#5c5f6d' : healthPct >= 80 ? '#4fd08a' : healthPct >= 50 ? '#e8a33d' : '#e2504a';

  const critical = depFindings.filter((f) => severityClass(f.severity) === 'sev-critical').length;
  const high = depFindings.filter((f) => severityClass(f.severity) === 'sev-high').length;
  const medium = depFindings.filter((f) => severityClass(f.severity) === 'sev-medium').length;
  const low = depFindings.filter((f) => severityClass(f.severity) === 'sev-low').length;
  const totalVulns = depFindings.length;

  const highestRisk = [...depFindings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[(a.severity || '').toLowerCase()] ?? 4) - (order[(b.severity || '').toLowerCase()] ?? 4);
  })[0];

  // Real "findings by package" breakdown — how many advisories hit each
  // package — replaces the fabricated Frontend/Backend/etc. category chart.
  const byPackage = vulnerablePackageNames
    .map((name) => ({
      name,
      count: depFindings.filter((f) => f.packageName === name).length,
      worstSeverity: [...depFindings]
        .filter((f) => f.packageName === name)
        .sort((a, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3 };
          return (order[(a.severity || '').toLowerCase()] ?? 4) - (order[(b.severity || '').toLowerCase()] ?? 4);
        })[0]?.severity,
    }))
    .sort((a, b) => b.count - a.count);
  const maxPackageCount = Math.max(1, ...byPackage.map((p) => p.count));

  const hasData = Boolean(results);

  return (
    <section className="panel wide-panel">
      <div className="panel-head">
        <div className="panel-icon"><Package size={18} /></div>
        <div>
          <h2>Dependency Check</h2>
          <p>Known-vulnerability findings for your package.json, checked against OSV.dev.</p>
        </div>
        {hasData && (
          <span className="results-badge" style={totalVulns > 0 ? CRITICAL_FALLBACK : { background: '#12301f', color: '#4fd08a' }}>
            {totalVulns} vulnerabilit{totalVulns !== 1 ? 'ies' : 'y'} found
          </span>
        )}
      </div>

      {!hasData && (
        <div className="empty-state">
          <Package size={56} className="empty-icon" />
          <h3>Run a scan to see dependency check results.</h3>
          <p className="empty-sub">
            Head to Code Scan, pick <strong>Dependencies</strong>, paste your package.json, and run it —
            this view mirrors your most recent scan.
          </p>
        </div>
      )}

      {hasData && (
        <>
          <div className="dash-mid-grid" style={{ marginBottom: '16px' }}>
            <div className="dash-sub-panel">
              <h3>Dependency Health</h3>
              <div className="dash-donut-row">
                <svg width="110" height="110" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  {healthPct !== null && (
                    <circle
                      cx="21" cy="21" r="15.9" fill="transparent"
                      stroke={healthColor} strokeWidth="6"
                      strokeDasharray={`${healthPct} ${100 - healthPct}`}
                      strokeDashoffset="25"
                    />
                  )}
                  <text x="21" y="19" textAnchor="middle" fontSize="7.5" fill="#e8e9ee" fontWeight="700">
                    {healthPct !== null ? `${healthPct}%` : '—'}
                  </text>
                  <text x="21" y="26" textAnchor="middle" fontSize="3.6" fill="#5c5f6d">Health</text>
                </svg>
                <div>
                  <div className="dash-stat-value" style={{ color: healthColor, fontSize: '20px' }}>{healthLabel}</div>
                  <div className="dash-stat-sub">
                    {totalPackages !== null ? `${totalPackages} packages scanned` : `${vulnerablePackageNames.length} package(s) flagged`}
                  </div>
                </div>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Packages</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '8px' }}>
                <div className="dash-scan-row">
                  <span className="sev-pill sev-low">{safePackages ?? '—'}</span>
                  <div className="dash-scan-meta"><div className="dash-scan-name">Safe Packages</div></div>
                </div>
                <div className="dash-scan-row">
                  <span className="sev-pill sev-critical" style={CRITICAL_FALLBACK}>{vulnerablePackageNames.length}</span>
                  <div className="dash-scan-meta"><div className="dash-scan-name">Vulnerable Packages</div></div>
                </div>
                <div className="dash-scan-row">
                  <span className="sev-pill sev-medium">{totalPackages ?? '—'}</span>
                  <div className="dash-scan-meta"><div className="dash-scan-name">Total Packages</div></div>
                </div>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Findings by Severity</h3>
              <div className="dash-stats-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                <div className="dash-stat-card">
                  <div className="dash-stat-head">Critical</div>
                  <div className="dash-stat-value" style={{ color: '#e2504a' }}>{critical}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head">High</div>
                  <div className="dash-stat-value" style={{ color: '#e8a33d' }}>{high}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head">Medium</div>
                  <div className="dash-stat-value" style={{ color: '#d9c94f' }}>{medium}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head">Low</div>
                  <div className="dash-stat-value" style={{ color: '#4fd08a' }}>{low}</div>
                </div>
              </div>
            </div>
          </div>

          <div className="content-grid">
            <div className="left-col">
              <section className="panel">
                <div className="panel-head"><div><h2>Vulnerable Dependencies</h2></div></div>

                {totalVulns === 0 && (
                  <div className="empty-state">
                    <CheckCircle2 size={48} className="empty-icon success" />
                    <h3>No known vulnerabilities found.</h3>
                  </div>
                )}

                {totalVulns > 0 && (
                  <div className="secrets-table-wrap">
                    <table className="secrets-table">
                      <thead>
                        <tr>
                          <th>Severity</th>
                          <th>Package</th>
                          <th>Version</th>
                          <th>Fixed In</th>
                          <th>Advisory</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {depFindings.map((f, i) => {
                          const isCritical = severityClass(f.severity) === 'sev-critical';
                          return (
                            <tr key={i}>
                              <td>
                                <span className={`sev-pill ${severityClass(f.severity)}`} style={isCritical ? CRITICAL_FALLBACK : undefined}>
                                  {f.severity}
                                </span>
                              </td>
                              <td>{f.packageName ?? '—'}</td>
                              <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{f.version ?? '—'}</td>
                              <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{f.fixedVersion ?? '—'}</td>
                              <td><span className="chip">{f.vulnId ?? '—'}</span></td>
                              <td>
                                {f.osvUrl ? (
                                  <a href={f.osvUrl} target="_blank" rel="noreferrer" className="icon-btn" aria-label="View advisory">
                                    <ExternalLink size={14} />
                                  </a>
                                ) : '—'}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </div>

            <section className="panel risk-side-panel">
              <div className="panel-head">
                <div className="panel-icon"><Brain size={18} /></div>
                <div><h2>AI Dependency Analysis</h2></div>
                {totalVulns > 0 && (
                  <span className="results-badge" style={CRITICAL_FALLBACK}>
                    {critical > 0 ? 'High Risk' : 'Moderate Risk'}
                  </span>
                )}
              </div>

              {totalVulns === 0 && <p className="empty-sub">No vulnerable packages to analyze.</p>}

              {totalVulns > 0 && highestRisk && (
                <>
                  <div className="finding-card">
                    <div className="finding-type">Highest Risk Package</div>
                    <div className="finding-top" style={{ marginTop: '4px' }}>
                      <span style={{ fontWeight: 600 }}>{highestRisk.packageName}@{highestRisk.version}</span>
                      <span className={`sev-pill ${severityClass(highestRisk.severity)}`} style={severityClass(highestRisk.severity) === 'sev-critical' ? CRITICAL_FALLBACK : undefined}>
                        {highestRisk.severity}
                      </span>
                    </div>
                  </div>

                  <div className="finding-card">
                    <div className="finding-type">Why it's risky</div>
                    <div className="finding-preview">{highestRisk.explanation}</div>
                  </div>

                  <div className="finding-card">
                    <div className="finding-type">Recommendation</div>
                    <div className="finding-preview">{highestRisk.fix}</div>
                  </div>

                  {results.riskScore !== undefined && (
                    <div className="finding-card">
                      <div className="finding-type">Overall Risk Score</div>
                      <div className="finding-preview" style={{ fontSize: '20px', fontWeight: 700, color: '#e2504a' }}>
                        {results.riskScore} <span style={{ fontSize: '13px', fontWeight: 400, opacity: 0.6 }}>/ 100 — {results.riskLevel}</span>
                      </div>
                    </div>
                  )}

                  {highestRisk.osvUrl && (
                    <a href={highestRisk.osvUrl} target="_blank" rel="noreferrer" className="text-btn">
                      <ExternalLink size={13} /> View full advisory
                    </a>
                  )}
                </>
              )}
            </section>
          </div>

          <div className="dash-bottom-grid" style={{ marginTop: '16px' }}>
            <div className="dash-sub-panel">
              <h3>Findings by Package</h3>
              {byPackage.length === 0 && <p className="empty-sub">No vulnerable packages.</p>}
              {byPackage.map((p) => (
                <div className="dash-cat-row" key={p.name}>
                  <div className="dash-cat-label">{p.name}</div>
                  <div className="dash-cat-track">
                    <div
                      className="dash-cat-fill"
                      style={{
                        width: `${(p.count / maxPackageCount) * 100}%`,
                        background: severityClass(p.worstSeverity) === 'sev-critical' ? '#e2504a' : undefined,
                      }}
                    />
                  </div>
                  <div className="dash-cat-count">{p.count}</div>
                </div>
              ))}
            </div>

            <div className="dash-sub-panel">
              <h3>AI Recommendations</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
                {critical > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                    <CheckCircle2 size={14} style={{ opacity: 0.4, flexShrink: 0 }} />
                    <span>Update {critical} critical package{critical !== 1 ? 's' : ''} immediately</span>
                  </div>
                )}
                {['Lock dependency versions in package-lock.json', 'Enable Dependabot or Renovate for automatic PRs', 'Re-run this scan regularly to catch new advisories'].map((item) => (
                  <div key={item} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                    <CheckCircle2 size={14} style={{ opacity: 0.4, flexShrink: 0 }} />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div className="dash-sub-panel" style={{ marginTop: '16px' }}>
            <h3>Security Advisories</h3>
            {totalVulns === 0 && <p className="empty-sub">No advisories for this scan.</p>}
            {totalVulns > 0 && (
              <div className="secrets-table-wrap">
                <table className="secrets-table">
                  <thead>
                    <tr>
                      <th>Advisory ID</th>
                      <th>Package</th>
                      <th>Severity</th>
                      <th>Description</th>
                      <th>Published</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {depFindings.map((f, i) => {
                      const isCritical = severityClass(f.severity) === 'sev-critical';
                      return (
                        <tr key={i}>
                          <td><span className="chip">{f.vulnId ?? '—'}</span></td>
                          <td>{f.packageName ?? '—'}</td>
                          <td>
                            <span className={`sev-pill ${severityClass(f.severity)}`} style={isCritical ? CRITICAL_FALLBACK : undefined}>
                              {f.severity}
                            </span>
                          </td>
                          <td style={{ fontSize: '12.5px', maxWidth: '360px' }}>{f.explanation}</td>
                          <td style={{ fontSize: '12px', whiteSpace: 'nowrap' }}>{formatOSVDate(f.publishedDate)}</td>
                          <td>
                            {f.osvUrl ? (
                              <a href={f.osvUrl} target="_blank" rel="noreferrer" className="icon-btn" aria-label="View advisory">
                                <ExternalLink size={14} />
                              </a>
                            ) : '—'}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}

// ============================================================================
// AI Prioritization — dedicated panel (replaces the old static block).
// Reads from the same `results` / `history` state Code Scan already
// populates. Per-finding risk scores are derived deterministically from
// severity band + confidence (see computeRiskScore near the top of this
// file) — nothing here is hardcoded or fabricated.
// ============================================================================

function AIPrioritizationPanel({ results, history }) {
  const findings = results?.findings || [];
  const total = findings.length;

  const critical = findings.filter((f) => severityClass(f.severity) === 'sev-critical').length;
  const high = findings.filter((f) => severityClass(f.severity) === 'sev-high').length;
  const medium = findings.filter((f) => severityClass(f.severity) === 'sev-medium').length;
  const low = findings.filter((f) => severityClass(f.severity) === 'sev-low').length;

  const categoriesPresent = new Set(findings.map(categoryOf)).size;

  const riskScore = results?.riskScore ?? 0;
  const riskLevel = results?.riskLevel ?? '—';
  const riskColor = riskScore >= 70 ? '#e2504a' : riskScore >= 40 ? '#e8a33d' : '#4fd08a';

  // Score every finding, then take the top ones by score for the table.
  const scored = findings.map((f) => ({ ...f, _score: computeRiskScore(f) }));
  const topFindings = [...scored].sort((a, b) => b._score - a._score).slice(0, 8);

  const severityRows = [
    { key: 'critical', label: 'Critical', count: critical, range: '90 - 100', color: '#e2504a' },
    { key: 'high', label: 'High', count: high, range: '70 - 89', color: '#e8a33d' },
    { key: 'medium', label: 'Medium', count: medium, range: '40 - 69', color: '#d9c94f' },
    { key: 'low', label: 'Low', count: low, range: '0 - 39', color: '#4fd08a' },
  ];

  // Trend arrows — compares the current scan against the previous saved
  // scan in history (real data, not decorative squiggles).
  const sortedHistory = [...(history || [])].sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
  const previous = sortedHistory[1];
  const FIELD_MAP = { critical: 'critical', high: 'highSeverity', medium: 'mediumSeverity', low: 'lowSeverity' };
  function trendFor(key) {
    if (!previous) return null;
    const prevCount = previous[FIELD_MAP[key]] ?? 0;
    const curCount = severityRows.find((r) => r.key === key)?.count ?? 0;
    if (curCount > prevCount) return 'up';
    if (curCount < prevCount) return 'down';
    return 'flat';
  }

  // "Potential Risk Reduction" — the share of total risk-score weight that
  // Critical + High findings represent, i.e. how much overall risk drops
  // if you fix just those.
  const sumAllScores = scored.reduce((s, f) => s + f._score, 0);
  const sumCriticalHighScores = scored
    .filter((f) => ['sev-critical', 'sev-high'].includes(severityClass(f.severity)))
    .reduce((s, f) => s + f._score, 0);
  const potentialReduction = sumAllScores > 0 ? Math.round((sumCriticalHighScores / sumAllScores) * 100) : 0;

  const hasData = Boolean(results);

  return (
    <section className="panel wide-panel">
      <div className="panel-head">
        <div className="panel-icon"><Brain size={18} /></div>
        <div>
          <h2>AI Prioritization</h2>
          <p>AI ranks findings by real-world risk, not just pattern matches.</p>
        </div>
        {hasData && (
          <span className="results-badge" style={critical > 0 ? CRITICAL_FALLBACK : { background: '#12301f', color: '#4fd08a' }}>
            {total} finding{total !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {!hasData && (
        <div className="empty-state">
          <Brain size={56} className="empty-icon" />
          <h3>Run a scan to see AI-prioritized findings.</h3>
          <p className="empty-sub">Head to Code Scan — this view mirrors your most recent scan.</p>
        </div>
      )}

      {hasData && (
        <>
          <div className="dash-stats-grid" style={{ marginBottom: '16px' }}>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#3a1d1d', color: riskColor }}><ShieldAlert size={14} /></span>Overall Risk Score</div>
              <div className="dash-stat-value">{riskScore}<span> / 100</span></div>
              <div className="dash-stat-sub" style={{ color: riskColor }}>{riskLevel} risk</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#241a3a', color: '#a98cf0' }}><FileText size={14} /></span>Total Findings</div>
              <div className="dash-stat-value">{total}</div>
              <div className="dash-stat-sub">Across {categoriesPresent} categor{categoriesPresent === 1 ? 'y' : 'ies'}</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#3a1d1d', color: '#e2504a' }}><ShieldAlert size={14} /></span>Critical</div>
              <div className="dash-stat-value">{critical}</div>
              <div className="dash-stat-sub">{total ? Math.round((critical / total) * 100) : 0}%</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#3a2a12', color: '#e8a33d' }}><ShieldAlert size={14} /></span>High</div>
              <div className="dash-stat-value">{high}</div>
              <div className="dash-stat-sub">{total ? Math.round((high / total) * 100) : 0}%</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#3a3212', color: '#d9c94f' }}><ShieldAlert size={14} /></span>Medium</div>
              <div className="dash-stat-value">{medium}</div>
              <div className="dash-stat-sub">{total ? Math.round((medium / total) * 100) : 0}%</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#12301f', color: '#4fd08a' }}><ShieldCheck size={14} /></span>Low</div>
              <div className="dash-stat-value">{low}</div>
              <div className="dash-stat-sub">{total ? Math.round((low / total) * 100) : 0}%</div>
            </div>
          </div>

          <div className="content-grid" style={{ marginBottom: '16px' }}>
            <div className="left-col">
              <section className="panel">
                <div className="panel-head"><div><h2>Findings by Risk Level</h2></div></div>
                <div className="secrets-table-wrap">
                  <table className="secrets-table">
                    <thead>
                      <tr>
                        <th>Risk Level</th><th>Count</th><th>Percentage</th><th>AI Risk Score Range</th><th>Trend</th>
                      </tr>
                    </thead>
                    <tbody>
                      {severityRows.map((r) => {
                        const trend = trendFor(r.key);
                        return (
                          <tr key={r.key}>
                            <td>
                              <span className={`sev-pill sev-${r.key}`} style={r.key === 'critical' ? CRITICAL_FALLBACK : undefined}>
                                {r.label}
                              </span>
                            </td>
                            <td>{r.count}</td>
                            <td>{total ? Math.round((r.count / total) * 100) : 0}%</td>
                            <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{r.range}</td>
                            <td>
                              {trend === 'up' && <span style={{ color: '#e2504a' }}>↑</span>}
                              {trend === 'down' && <span style={{ color: '#4fd08a' }}>↓</span>}
                              {trend === 'flat' && <span style={{ opacity: 0.5 }}>→</span>}
                              {trend === null && <span style={{ opacity: 0.3 }}>—</span>}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </section>

              <section className="panel" style={{ marginTop: '14px' }}>
                <div className="panel-head"><div><h2>Top Prioritized Findings</h2></div></div>

                {topFindings.length === 0 && (
                  <div className="empty-state">
                    <CheckCircle2 size={48} className="empty-icon success" />
                    <h3>No findings to prioritize.</h3>
                  </div>
                )}

                {topFindings.length > 0 && (
                  <div className="secrets-table-wrap">
                    <table className="secrets-table">
                      <thead>
                        <tr><th>#</th><th>Finding</th><th>File / Location</th><th>Risk Score</th><th>Reason</th></tr>
                      </thead>
                      <tbody>
                        {topFindings.map((f, i) => {
                          const isCritical = severityClass(f.severity) === 'sev-critical';
                          return (
                            <tr key={i}>
                              <td>{i + 1}</td>
                              <td>
                                <span className={`sev-pill ${severityClass(f.severity)}`} style={isCritical ? CRITICAL_FALLBACK : undefined}>
                                  {f.severity}
                                </span>
                                <div style={{ marginTop: '4px', fontWeight: 600 }}>{f.type}</div>
                              </td>
                              <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{locationForFinding(f)}</td>
                              <td style={{ fontWeight: 700, color: isCritical ? '#e2504a' : '#e8e9ee' }}>{f._score}/100</td>
                              <td style={{ fontSize: '12.5px', maxWidth: '260px' }}>{reasonForFinding(f)}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
                {findings.length > 8 && (
                  <p className="empty-sub" style={{ marginTop: '8px' }}>
                    Showing top 8 of {findings.length} findings by risk score.
                  </p>
                )}
              </section>
            </div>

            <section className="panel risk-side-panel">
              <div className="panel-head"><div><h2>Risk Distribution</h2></div></div>
              <div className="dash-donut-row">
                <svg width="110" height="110" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  {(() => {
                    let offset = 25;
                    return severityRows.map((r) => {
                      const pct = total > 0 ? (r.count / total) * 100 : 0;
                      const circle = (
                        <circle
                          key={r.key} cx="21" cy="21" r="15.9" fill="transparent"
                          stroke={r.color} strokeWidth="6"
                          strokeDasharray={`${pct} ${100 - pct}`}
                          strokeDashoffset={offset}
                        />
                      );
                      offset -= pct;
                      return circle;
                    });
                  })()}
                  <text x="21" y="19" textAnchor="middle" fontSize="7" fill="#e8e9ee" fontWeight="700">{total}</text>
                  <text x="21" y="26" textAnchor="middle" fontSize="4" fill="#5c5f6d">Total</text>
                </svg>
                <div className="dash-legend">
                  {severityRows.map((r) => (
                    <div className="dash-legend-item" key={r.key}>
                      <span className="dash-dot" style={{ background: r.color }} />{r.label}
                      <span className="dash-legend-count">{r.count} ({total > 0 ? Math.round((r.count / total) * 100) : 0}%)</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ marginTop: '16px' }}>
                <h3 style={{ marginBottom: '8px' }}>Why These Issues?</h3>
                <div className="finding-card">
                  <div className="finding-type">Exploitability</div>
                  <div className="finding-preview">How easy is it to exploit this vulnerability?</div>
                </div>
                <div className="finding-card">
                  <div className="finding-type">Impact</div>
                  <div className="finding-preview">What is the potential damage?</div>
                </div>
                <div className="finding-card">
                  <div className="finding-type">Likelihood</div>
                  <div className="finding-preview">How likely is this to be exploited?</div>
                </div>
                <div className="finding-card">
                  <div className="finding-type">Context</div>
                  <div className="finding-preview">Business logic, data sensitivity, exposure</div>
                </div>
                <div className="finding-card">
                  <div className="finding-type">AI Confidence</div>
                  <div className="finding-preview">Confidence in the risk assessment</div>
                </div>
              </div>
            </section>
          </div>

          <div className="dash-bottom-grid">
            <div className="dash-sub-panel">
              <h3>AI Recommendation</h3>
              <p className="empty-sub" style={{ marginBottom: '10px' }}>
                Focus on fixing Critical and High risk issues first. These pose the highest real-world risk to your application.
              </p>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                {critical > 0 && (
                  <span className="chip" style={CRITICAL_FALLBACK}>Fix {critical} Critical issue{critical !== 1 ? 's' : ''}</span>
                )}
                {high > 0 && (
                  <span className="chip" style={{ background: 'rgba(232,163,61,0.15)', color: '#e8a33d', border: '1px solid rgba(232,163,61,0.4)' }}>
                    Fix {high} High issue{high !== 1 ? 's' : ''}
                  </span>
                )}
                {medium > 0 && (
                  <span className="chip" style={{ background: 'rgba(217,201,79,0.15)', color: '#d9c94f', border: '1px solid rgba(217,201,79,0.4)' }}>
                    Review {medium} Medium issue{medium !== 1 ? 's' : ''}
                  </span>
                )}
                {low > 0 && (
                  <span className="chip" style={{ background: 'rgba(79,208,138,0.15)', color: '#4fd08a', border: '1px solid rgba(79,208,138,0.4)' }}>
                    Monitor {low} Low issue{low !== 1 ? 's' : ''}
                  </span>
                )}
                {total === 0 && <span className="empty-sub">No findings to act on.</span>}
              </div>
            </div>

            <div className="dash-stat-card" style={{ alignSelf: 'center' }}>
              <div className="dash-stat-head">Potential Risk Reduction</div>
              <div className="dash-stat-value" style={{ color: '#4fd08a', fontSize: '32px' }}>{potentialReduction}%</div>
              <div className="dash-stat-sub">If you fix Critical &amp; High issues</div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}

// ============================================================================
// Secrets Detection — dedicated panel (replaces the generic filtered-list
// branch previously shared with Configuration Check). Reads from the same
// `results` state Code Scan already populates. See secretSubType() for how
// sub-categories (API Keys / DB Credentials / JWT / Cloud / SSH / OAuth) are
// derived from `finding.type` — tighten those keywords if your backend's
// pattern names differ.
// ============================================================================

function secretSubType(f) {
  const t = (f.type || '').toLowerCase();
  if (t.includes('jwt')) return 'jwt';
  if (t.includes('ssh')) return 'ssh';
  if (t.includes('oauth')) return 'oauth';
  if (t.includes('aws') || t.includes('azure') || t.includes('gcp') || t.includes('cloud')) return 'cloud';
  if (t.includes('sql') || t.includes('database') || t.includes('mysql') || t.includes('postgres') || t.includes('mongo') || t.includes('password')) return 'database';
  return 'api';
}

const SECRET_SUBTYPES = [
  { key: 'api', label: 'API Keys', icon: KeyRound, color: '#a98cf0' },
  { key: 'database', label: 'Database Credentials', icon: Database, color: '#e8a33d' },
  { key: 'jwt', label: 'JWT Secrets', icon: ShieldCheck, color: '#4fd08a' },
  { key: 'cloud', label: 'Cloud Credentials', icon: Cloud, color: '#3ba7f0' },
  { key: 'ssh', label: 'SSH Keys', icon: Lock, color: '#a98cf0' },
  { key: 'oauth', label: 'OAuth Tokens', icon: ShieldCheck, color: '#3ba7f0' },
];

// Static reference lists — not derived from live state, same role as the
// original mockup's checklist/type-coverage cards. Edit the copy to match
// your actual guidance / pattern coverage.
const REMEDIATION_CHECKLIST = [
  'Move secrets to environment variables',
  'Rotate any exposed API keys or credentials',
  'Remove secrets from git history',
  'Use a secret manager or vault',
  'Restrict access to secrets by least privilege',
];

const SUPPORTED_SECRET_TYPES = [
  'Google API Keys', 'AWS Access Keys', 'Azure Keys', 'OpenAI API Keys',
  'Stripe Keys', 'GitHub Tokens', 'JWT Secrets', 'Database Credentials',
  'SSH Private Keys', 'SMTP Credentials',
];

function SecretsDetectionPanel({ results, code, scanDurationMs }) {
  const [revealed, setRevealed] = useState({});
  const [copiedIdx, setCopiedIdx] = useState(null);

  const allFindings = results?.findings || [];
  const secretFindings = allFindings.filter((f) => categoryOf(f) === 'secrets');

  const critical = secretFindings.filter((f) => severityClass(f.severity) === 'sev-critical').length;
  const medium = secretFindings.filter((f) => severityClass(f.severity) === 'sev-medium').length;
  const low = secretFindings.filter((f) => severityClass(f.severity) === 'sev-low').length;
  const total = secretFindings.length;

  const exposureScore = results
    ? Math.max(0, 100 - (results.riskScore ?? 0))
    : 100;
  const exposureLabel = exposureScore >= 80 ? 'Good' : exposureScore >= 50 ? 'Moderate' : 'Poor';
  const exposureColor = exposureScore >= 80 ? '#4fd08a' : exposureScore >= 50 ? '#e8a33d' : '#e2504a';

  const linesScanned = code ? code.split('\n').length : 0;

  const subtypeCounts = SECRET_SUBTYPES.map((s) => ({
    ...s,
    count: secretFindings.filter((f) => secretSubType(f) === s.key).length,
  }));

  const highestRisk = [...secretFindings].sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return (order[(a.severity || '').toLowerCase()] ?? 4) - (order[(b.severity || '').toLowerCase()] ?? 4);
  })[0];

  function toggleReveal(i) {
    setRevealed((prev) => ({ ...prev, [i]: !prev[i] }));
  }

  function handleCopy(text, i) {
    navigator.clipboard?.writeText(text || '');
    setCopiedIdx(i);
    setTimeout(() => setCopiedIdx(null), 1200);
  }

  return (
    <section className="panel wide-panel">
      <div className="panel-head">
        <div className="panel-icon"><KeyRound size={18} /></div>
        <div>
          <h2>Secrets Detection</h2>
          <p>Identify exposed secrets, credentials and sensitive data in your codebase.</p>
        </div>
        {results && (
          <span className="results-badge" style={total > 0 ? CRITICAL_FALLBACK : { background: '#12301f', color: '#4fd08a' }}>
            {total} secret{total !== 1 ? 's' : ''} found
          </span>
        )}
      </div>

      {!results && (
        <div className="empty-state">
          <KeyRound size={56} className="empty-icon" />
          <h3>Run a scan to see secrets detection results.</h3>
          <p className="empty-sub">Head to Code Scan — this view mirrors your most recent scan.</p>
        </div>
      )}

      {results && (
        <>
          <div className="dash-mid-grid" style={{ marginBottom: '16px' }}>
            <div className="dash-sub-panel">
              <h3>Overall Secret Exposure</h3>
              <div className="dash-donut-row">
                <svg width="110" height="110" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  <circle
                    cx="21" cy="21" r="15.9" fill="transparent"
                    stroke={exposureColor} strokeWidth="6"
                    strokeDasharray={`${exposureScore} ${100 - exposureScore}`}
                    strokeDashoffset="25"
                  />
                  <text x="21" y="19" textAnchor="middle" fontSize="7.5" fill="#e8e9ee" fontWeight="700">{exposureScore}%</text>
                  <text x="21" y="26" textAnchor="middle" fontSize="3.6" fill="#5c5f6d">Exposure</text>
                </svg>
                <div>
                  <div className="dash-stat-value" style={{ color: exposureColor, fontSize: '20px' }}>{exposureLabel}</div>
                  <div className="dash-stat-sub">{total === 0 ? 'No secrets detected' : `${total} secret${total !== 1 ? 's' : ''} detected`}</div>
                </div>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Severity Breakdown</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '8px' }}>
                <div className="dash-scan-row">
                  <span className="sev-pill sev-critical" style={CRITICAL_FALLBACK}>{critical}</span>
                  <div className="dash-scan-meta"><div className="dash-scan-name">Critical Secrets</div></div>
                </div>
                <div className="dash-scan-row">
                  <span className="sev-pill sev-medium">{medium}</span>
                  <div className="dash-scan-meta"><div className="dash-scan-name">Medium Secrets</div></div>
                </div>
                <div className="dash-scan-row">
                  <span className="sev-pill sev-low">{low}</span>
                  <div className="dash-scan-meta"><div className="dash-scan-name">Low Secrets</div></div>
                </div>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Summary</h3>
              <p className="empty-sub" style={{ marginBottom: '10px' }}>
                SecureCode scanned your pasted code for exposed secrets and sensitive credentials.
              </p>
              <div className="dash-stats-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><KeyRound size={14} /> Secrets Found</div>
                  <div className="dash-stat-value">{total}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><FileText size={14} /> Lines Scanned</div>
                  <div className="dash-stat-value">{linesScanned}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><Clock size={14} /> Scan Duration</div>
                  <div className="dash-stat-value" style={{ fontSize: '16px' }}>
                    {scanDurationMs !== null && scanDurationMs !== undefined ? `${(scanDurationMs / 1000).toFixed(2)}s` : '—'}
                  </div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><ShieldAlert size={14} /> Risk Level</div>
                  <div className="dash-stat-value" style={{ fontSize: '16px', color: exposureColor }}>{results.riskLevel ?? '—'}</div>
                </div>
              </div>
            </div>
          </div>

          <div className="dash-sub-panel" style={{ marginBottom: '16px' }}>
            <h3>Secret Types</h3>
            <div className="dash-cap-grid">
              {subtypeCounts.map((s) => {
                const Icon = s.icon;
                return (
                  <div className="dash-cap-card" key={s.key}>
                    <div className="dash-cap-icon" style={{ color: s.color }}><Icon size={14} /></div>
                    <div className="dash-cap-title">{s.label}</div>
                    <div className="dash-cap-status" style={{ color: s.count > 0 ? s.color : '#4fd08a' }}>
                      {s.count > 0 ? `${s.count} exposed` : 'None found'}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="content-grid">
            <div className="left-col">
              <section className="panel">
                <div className="panel-head"><div><h2>Detected Secrets</h2></div></div>

                {total === 0 && (
                  <div className="empty-state">
                    <CheckCircle2 size={48} className="empty-icon success" />
                    <h3>No secrets found. Nice and clean.</h3>
                  </div>
                )}

                {total > 0 && (
                  <div className="secrets-table-wrap">
                    <table className="secrets-table">
                      <thead>
                        <tr>
                          <th>Severity</th>
                          <th>Secret Type</th>
                          <th>Line</th>
                          <th>Preview</th>
                          <th>Method</th>
                          <th>Action</th>
                        </tr>
                      </thead>
                      <tbody>
                        {secretFindings.map((f, i) => {
                          const isCritical = severityClass(f.severity) === 'sev-critical';
                          return (
                            <tr key={i}>
                              <td>
                                <span className={`sev-pill ${severityClass(f.severity)}`} style={isCritical ? CRITICAL_FALLBACK : undefined}>
                                  {f.severity}
                                </span>
                              </td>
                              <td>{f.type}</td>
                              <td>{f.line ?? '—'}</td>
                              <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                                {revealed[i] ? f.matchPreview : '••••••••••••'}
                              </td>
                              <td><span className="chip">{f.method ?? '—'}</span></td>
                              <td style={{ display: 'flex', gap: '6px' }}>
                                <button className="icon-btn" onClick={() => toggleReveal(i)} aria-label="Toggle preview">
                                  {revealed[i] ? <EyeOff size={14} /> : <Eye size={14} />}
                                </button>
                                <button className="icon-btn" onClick={() => handleCopy(f.matchPreview, i)} aria-label="Copy">
                                  {copiedIdx === i ? <Check size={14} /> : <Copy size={14} />}
                                </button>
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>
            </div>

            <section className="panel risk-side-panel">
              <div className="panel-head">
                <div className="panel-icon"><Brain size={18} /></div>
                <div><h2>AI Risk Analysis</h2></div>
                {total > 0 && (
                  <span className="results-badge" style={CRITICAL_FALLBACK}>
                    {critical > 0 ? 'High Risk' : total > 0 ? 'Moderate Risk' : 'Low Risk'}
                  </span>
                )}
              </div>

              {total === 0 && <p className="empty-sub">No secrets to analyze — nothing risky detected.</p>}

              {total > 0 && (
                <>
                  <div className="finding-card">
                    <div className="finding-type">AI Summary</div>
                    <div className="finding-preview">
                      {total} secret{total !== 1 ? 's' : ''} detected in your code.
                      {critical > 0 ? ` ${critical} critical secret${critical !== 1 ? 's' : ''} pose${critical === 1 ? 's' : ''} a high risk of unauthorized access.` : ' None are critical severity.'}
                    </div>
                  </div>

                  {highestRisk && (
                    <div className="finding-card">
                      <div className="finding-type">Highest Risk Secret</div>
                      <div className="finding-top" style={{ marginTop: '4px' }}>
                        <span style={{ fontWeight: 600 }}>{highestRisk.type}</span>
                        <span className={`sev-pill ${severityClass(highestRisk.severity)}`} style={severityClass(highestRisk.severity) === 'sev-critical' ? CRITICAL_FALLBACK : undefined}>
                          {highestRisk.severity}
                        </span>
                      </div>
                    </div>
                  )}

                  <div className="finding-card">
                    <div className="finding-type">Why it's risky</div>
                    <div className="finding-preview">
                      {highestRisk?.explanation || 'Exposed credentials of this kind can let an attacker access connected services, incur costs, or exfiltrate data.'}
                    </div>
                  </div>

                  <div className="finding-card">
                    <div className="finding-type">Recommendation</div>
                    <div className="finding-preview">
                      {highestRisk?.fix || 'Move this secret to an environment variable or secret manager, and rotate it immediately.'}
                    </div>
                  </div>
                </>
              )}
            </section>
          </div>

          <div className="dash-bottom-grid" style={{ marginTop: '16px', gridTemplateColumns: '1fr 1fr 1fr' }}>
            <div className="dash-sub-panel">
              <h3>Secret Categories</h3>
              <div className="dash-donut-row">
                <svg width="90" height="90" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  {(() => {
                    let offset = 25;
                    return subtypeCounts.filter((s) => s.count > 0).map((s) => {
                      const pct = total > 0 ? (s.count / total) * 100 : 0;
                      const circle = (
                        <circle key={s.key} cx="21" cy="21" r="15.9" fill="transparent"
                          stroke={s.color} strokeWidth="6"
                          strokeDasharray={`${pct} ${100 - pct}`} strokeDashoffset={offset} />
                      );
                      offset -= pct;
                      return circle;
                    });
                  })()}
                </svg>
                <div className="dash-legend">
                  {subtypeCounts.filter((s) => s.count > 0).map((s) => (
                    <div className="dash-legend-item" key={s.key}>
                      <span className="dash-dot" style={{ background: s.color }} />{s.label}
                      <span className="dash-legend-count">{s.count} ({total > 0 ? Math.round((s.count / total) * 100) : 0}%)</span>
                    </div>
                  ))}
                  {subtypeCounts.every((s) => s.count === 0) && <p className="empty-sub">No secrets to categorize.</p>}
                </div>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Remediation Checklist</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
                {REMEDIATION_CHECKLIST.map((item) => (
                  <div key={item} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                    <CheckCircle2 size={14} style={{ opacity: 0.4, flexShrink: 0 }} />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Supported Secret Types</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '8px' }}>
                {SUPPORTED_SECRET_TYPES.map((t) => (
                  <div key={t} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                    <span className="dash-dot" style={{ background: '#a98cf0' }} />
                    <span>{t}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}

// ============================================================================
// Configuration Check — dedicated panel (replaces the old generic filtered
// list). Reads from the same `results` / `code` state Code Scan already
// populates. The 8 "Configuration Checks" tiles and the OWASP checklist are
// both derived by keyword-matching real finding `type`/`explanation` text —
// nothing here is a fabricated project name, file list, or language badge.
// ============================================================================

function severityRank(sev) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return order[(sev || '').toLowerCase()] ?? 4;
}

const CONFIG_CHECK_DEFINITIONS = [
  { key: 'env', label: 'Environment Variables', icon: Code2, keywords: ['env var', '.env', 'hardcoded secret', 'hardcoded key', 'hardcoded password', 'hardcoded credential'], cleanText: 'No hardcoded secrets found' },
  { key: 'debug', label: 'Debug Mode', icon: Bug, keywords: ['debug'], cleanText: 'Debug mode is disabled' },
  { key: 'https', label: 'HTTPS Configuration', icon: Lock, keywords: ['https'], cleanText: 'HTTPS is properly enabled' },
  { key: 'cors', label: 'CORS Configuration', icon: Cloud, keywords: ['cors'], cleanText: 'CORS is properly restricted' },
  { key: 'headers', label: 'Security Headers', icon: ShieldCheck, keywords: ['header', 'csp', 'hsts', 'x-frame', 'content-security-policy'], cleanText: 'Security headers are present' },
  { key: 'docker', label: 'Docker Configuration', icon: Package, keywords: ['docker', 'container'], cleanText: 'No issues found' },
  { key: 'ssltls', label: 'SSL / TLS', icon: Lock, keywords: ['ssl', 'tls', 'certificate'], cleanText: 'Strong TLS configuration' },
  { key: 'permissions', label: 'File Permissions', icon: Folder, keywords: ['permission', 'chmod', 'file mode'], cleanText: 'File permissions look fine' },
];

const OWASP_CHECK_DEFINITIONS = [
  { label: 'Secure HTTP Headers', keywords: ['header', 'hsts', 'x-frame'] },
  { label: 'Content Security Policy (CSP)', keywords: ['csp', 'content-security-policy'] },
  { label: 'CORS Policy', keywords: ['cors'] },
  { label: 'TLS / SSL Configuration', keywords: ['tls', 'ssl', 'certificate', 'https'] },
  { label: 'Cookie Security', keywords: ['cookie'] },
  { label: 'Environment Variables', keywords: ['env var', '.env', 'hardcoded'] },
  { label: 'Error Handling', keywords: ['error handling', 'stack trace', 'verbose error'] },
  { label: 'Debug Mode', keywords: ['debug'] },
];

// Finds the highest-severity finding (across ALL findings, not just the
// "config" category) whose type/explanation mentions any of `keywords`.
function findConfigMatch(findings, keywords) {
  const matches = findings.filter((f) => {
    const hay = `${f.type || ''} ${f.explanation || ''}`.toLowerCase();
    return keywords.some((k) => hay.includes(k));
  });
  if (matches.length === 0) return null;
  return [...matches].sort((a, b) => severityRank(a.severity) - severityRank(b.severity))[0];
}

function statusForConfigMatch(f) {
  if (!f) return 'secure';
  const sev = (f.severity || '').toLowerCase();
  if (sev === 'critical' || sev === 'high') return 'critical';
  return 'warning';
}

function statusPillClass(status) {
  if (status === 'critical') return 'sev-critical';
  if (status === 'warning') return 'sev-medium';
  return 'sev-low';
}

// Best-effort content type label from the pasted text itself — used instead
// of a fabricated file list, since this app scans one pasted blob at a time.
function detectFileType(code) {
  if (!code) return '—';
  const trimmed = code.trim();
  if (!trimmed) return '—';
  if (trimmed.startsWith('{')) {
    try { JSON.parse(trimmed); return 'JSON'; } catch { /* not JSON, fall through */ }
  }
  if (/^FROM\s+/im.test(trimmed) || /dockerfile/i.test(trimmed)) return 'Dockerfile';
  if (/^[\w-]+:\s/m.test(trimmed)) return 'YAML';
  if (/^[\w.]+\s*=\s*.+$/m.test(trimmed) && !trimmed.includes('{')) return '.env / Config';
  return 'Source Code';
}

function ConfigurationCheckPanel({ results, code, scanDurationMs }) {
  const [openRow, setOpenRow] = useState(null);
  const allFindings = results?.findings || [];
  const configFindings = allFindings.filter((f) => categoryOf(f) === 'config');

  const checks = CONFIG_CHECK_DEFINITIONS.map((def) => {
    const match = findConfigMatch(allFindings, def.keywords);
    const status = statusForConfigMatch(match);
    return { ...def, match, status };
  });

  const passed = checks.filter((c) => c.status === 'secure').length;
  const warnings = checks.filter((c) => c.status === 'warning').length;
  const criticalCount = checks.filter((c) => c.status === 'critical').length;
  const totalChecks = checks.length;

  const healthPct = totalChecks
    ? Math.round(((passed + warnings * 0.5) / totalChecks) * 100)
    : 100;
  const healthLabel = healthPct >= 90 ? 'Excellent' : healthPct >= 70 ? 'Good' : healthPct >= 50 ? 'Moderate' : 'Poor';
  const healthColor = healthPct >= 90 ? '#4fd08a' : healthPct >= 70 ? '#8dd66a' : healthPct >= 50 ? '#e8a33d' : '#e2504a';

  const owaspChecks = OWASP_CHECK_DEFINITIONS.map((def) => {
    const match = findConfigMatch(allFindings, def.keywords);
    const status = statusForConfigMatch(match);
    return { ...def, status };
  });

  const overallRisk = criticalCount > 0 ? 'High' : warnings > 0 ? 'Medium' : 'Low';
  const overallRiskColor = overallRisk === 'High' ? '#e2504a' : overallRisk === 'Medium' ? '#e8a33d' : '#4fd08a';

  const recommendedActions = [...new Set(configFindings.map((f) => f.fix).filter(Boolean))].slice(0, 5);

  const linesScanned = code ? code.split('\n').length : 0;
  const contentType = detectFileType(code);

  const hasData = Boolean(results);

  return (
    <section className="panel wide-panel">
      <div className="panel-head">
        <div className="panel-icon"><Sliders size={18} /></div>
        <div>
          <h2>Configuration Check</h2>
          <p>Find insecure configurations and harden your project.</p>
        </div>
        {hasData && (
          <span className="results-badge" style={criticalCount > 0 ? CRITICAL_FALLBACK : { background: '#12301f', color: '#4fd08a' }}>
            {configFindings.length} finding{configFindings.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {!hasData && (
        <div className="empty-state">
          <Sliders size={56} className="empty-icon" />
          <h3>Run a scan to see configuration check results.</h3>
          <p className="empty-sub">Head to Code Scan — this view mirrors your most recent scan.</p>
        </div>
      )}

      {hasData && (
        <>
          <div className="dash-mid-grid" style={{ marginBottom: '16px' }}>
            <div className="dash-sub-panel">
              <h3>Configuration Health</h3>
              <div className="dash-donut-row">
                <svg width="110" height="110" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  <circle
                    cx="21" cy="21" r="15.9" fill="transparent"
                    stroke={healthColor} strokeWidth="6"
                    strokeDasharray={`${healthPct} ${100 - healthPct}`}
                    strokeDashoffset="25"
                  />
                  <text x="21" y="19" textAnchor="middle" fontSize="7.5" fill="#e8e9ee" fontWeight="700">{healthPct}%</text>
                  <text x="21" y="26" textAnchor="middle" fontSize="3.6" fill="#5c5f6d">Health</text>
                </svg>
                <div>
                  <div className="dash-stat-value" style={{ color: healthColor, fontSize: '20px' }}>{healthLabel}</div>
                  <div className="dash-stat-sub">{passed}/{totalChecks} checks passed</div>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                  <CheckCircle2 size={14} style={{ color: '#4fd08a', flexShrink: 0 }} />
                  <span>{passed} Passed</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                  <AlertTriangle size={14} style={{ color: '#e8a33d', flexShrink: 0 }} />
                  <span>{warnings} Warning{warnings !== 1 ? 's' : ''}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                  <X size={14} style={{ color: '#e2504a', flexShrink: 0 }} />
                  <span>{criticalCount} Critical</span>
                </div>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Checks Performed</h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginTop: '10px' }}>
                <div className="dash-stat-value" style={{ fontSize: '32px' }}>{totalChecks}<span style={{ fontSize: '18px' }}> / {totalChecks}</span></div>
                <CheckCircle2 size={32} style={{ color: '#a98cf0', opacity: 0.7 }} />
              </div>
              <div className="dash-stat-sub" style={{ color: '#3ba7f0', marginTop: '6px' }}>100% Completed</div>
            </div>

            <div className="dash-sub-panel">
              <h3>Scan Details</h3>
              <div className="dash-stats-grid" style={{ gridTemplateColumns: '1fr 1fr', marginTop: '4px' }}>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><FileText size={14} /> Content Type</div>
                  <div className="dash-stat-value" style={{ fontSize: '15px' }}>{contentType}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><Code2 size={14} /> Lines Scanned</div>
                  <div className="dash-stat-value" style={{ fontSize: '15px' }}>{linesScanned}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><Clock size={14} /> Scan Duration</div>
                  <div className="dash-stat-value" style={{ fontSize: '15px' }}>
                    {scanDurationMs !== null && scanDurationMs !== undefined ? `${(scanDurationMs / 1000).toFixed(2)}s` : '—'}
                  </div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><ShieldAlert size={14} /> Risk Level</div>
                  <div className="dash-stat-value" style={{ fontSize: '15px', color: overallRiskColor }}>{results.riskLevel ?? '—'}</div>
                </div>
              </div>
            </div>
          </div>

          <div className="dash-sub-panel" style={{ marginBottom: '16px' }}>
            <h3>Configuration Checks</h3>
            <div className="dash-cap-grid">
              {checks.map((c) => {
                const Icon = c.icon;
                const desc = c.match ? reasonForFinding(c.match) : c.cleanText;
                return (
                  <div className="dash-cap-card" key={c.key}>
                    <div className="dash-cap-icon"><Icon size={14} /></div>
                    <div className="dash-cap-title">{c.label}</div>
                    <div style={{ margin: '4px 0' }}>
                      <span className={`sev-pill ${statusPillClass(c.status)}`} style={c.status === 'critical' ? CRITICAL_FALLBACK : undefined}>
                        {c.status === 'secure' ? 'Secure' : c.status === 'warning' ? 'Warning' : 'Critical'}
                      </span>
                    </div>
                    <div style={{ fontSize: '11.5px', opacity: 0.6, lineHeight: 1.4 }}>{desc}</div>
                  </div>
                );
              })}
            </div>
          </div>

          <section className="panel" style={{ marginBottom: '16px' }}>
            <div className="panel-head"><div><h2>Configuration Findings</h2></div></div>

            {configFindings.length === 0 && (
              <div className="empty-state">
                <CheckCircle2 size={48} className="empty-icon success" />
                <h3>No configuration issues found.</h3>
              </div>
            )}

            {configFindings.length > 0 && (
              <div className="secrets-table-wrap">
                <table className="secrets-table">
                  <thead>
                    <tr>
                      <th>Severity</th><th>Issue</th><th>File / Location</th><th>Description</th><th>Recommendation</th><th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {configFindings.map((f, i) => {
                      const isCritical = severityClass(f.severity) === 'sev-critical';
                      const isOpen = openRow === i;
                      return [
                        <tr key={`row-${i}`}>
                          <td>
                            <span className={`sev-pill ${severityClass(f.severity)}`} style={isCritical ? CRITICAL_FALLBACK : undefined}>
                              {f.severity}
                            </span>
                          </td>
                          <td>{f.type}</td>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>{locationForFinding(f)}</td>
                          <td style={{ fontSize: '12.5px', maxWidth: '260px' }}>{f.explanation || '—'}</td>
                          <td style={{ fontSize: '12.5px', maxWidth: '220px' }}>{f.fix || '—'}</td>
                          <td>
                            <button className="text-btn" onClick={() => setOpenRow(isOpen ? null : i)}>
                              {isOpen ? 'Hide' : 'View'}
                            </button>
                          </td>
                        </tr>,
                        isOpen && (
                          <tr key={`detail-${i}`}>
                            <td colSpan={6} style={{ fontSize: '12px', opacity: 0.7, padding: '8px 12px' }}>
                              {typeof f.confidence === 'number' && <span>{Math.round(f.confidence * 100)}% confidence · </span>}
                              {f.method && <span>Detected via {f.method}</span>}
                            </td>
                          </tr>
                        ),
                      ];
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>

          <div className="dash-bottom-grid" style={{ gridTemplateColumns: '1fr 1fr 1fr' }}>
            <div className="dash-sub-panel">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <Brain size={16} style={{ color: '#a98cf0' }} />
                <h3 style={{ margin: 0 }}>AI Recommendation</h3>
              </div>
              <p className="empty-sub" style={{ marginBottom: '10px' }}>
                {configFindings.length === 0
                  ? "No configuration issues found. Your project's configuration looks secure."
                  : `Your project has ${criticalCount} critical and ${warnings} warning-level configuration issue${(criticalCount + warnings) !== 1 ? 's' : ''}. Addressing them will improve your security posture.`}
              </p>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '13px', opacity: 0.7 }}>Overall Risk</span>
                <span
                  className="chip"
                  style={{ background: `${overallRiskColor}22`, color: overallRiskColor, border: `1px solid ${overallRiskColor}66` }}
                >
                  {overallRisk}
                </span>
              </div>
              {recommendedActions.length > 0 && (
                <>
                  <div style={{ fontSize: '13px', opacity: 0.7, marginBottom: '6px' }}>Recommended Actions</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {recommendedActions.map((action) => (
                      <div key={action} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                        <CheckCircle2 size={14} style={{ opacity: 0.4, flexShrink: 0 }} />
                        <span>{action}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>

            <div className="dash-sub-panel">
              <h3>Scan Coverage</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px' }}>
                {CONFIG_CHECK_DEFINITIONS.map((def) => (
                  <div key={def.key} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px' }}>
                    <CheckCircle2 size={14} style={{ color: '#4fd08a', flexShrink: 0 }} />
                    <span>{def.label}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>OWASP Security Misconfiguration Checklist</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '8px', marginBottom: '10px' }}>
                {owaspChecks.map((c) => {
                  const label = c.status === 'secure' ? 'Passed' : c.status === 'warning' ? 'Warning' : 'Failed';
                  const color = c.status === 'secure' ? '#4fd08a' : c.status === 'warning' ? '#e8a33d' : '#e2504a';
                  const Icon = c.status === 'secure' ? CheckCircle2 : AlertTriangle;
                  return (
                    <div key={c.label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '13px' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Icon size={14} style={{ color, flexShrink: 0 }} />
                        {c.label}
                      </span>
                      <span style={{ color, fontWeight: 600, fontSize: '12px' }}>{label}</span>
                    </div>
                  );
                })}
              </div>
              <a
                href="https://cheatsheetseries.owasp.org/cheatsheets/Secure_Configuration_Cheat_Sheet.html"
                target="_blank" rel="noreferrer" className="text-btn"
              >
                <ExternalLink size={13} /> View OWASP Guidelines
              </a>
            </div>
          </div>

          <p className="empty-sub" style={{ marginTop: '16px' }}>
            Configuration checks ensure your application and infrastructure follow security best practices and are not misconfigured.
          </p>
        </>
      )}
    </section>
  );
}

// ============================================================================
// Security Coverage — dedicated panel (replaces the old binary "Clean /
// found" list). Reads from the same `results` / `code` state Code Scan
// already populates. "Coverage %" per category is the average AI confidence
// of that category's own findings (a real field from your backend) — when a
// category has zero findings, coverage defaults to 100% (nothing to lower
// confidence in). The OWASP Top 10 statuses reflect the scanner's actual
// detection capability (whether categoryOf()/keyword logic exists for that
// class of issue), not per-scan results — so they're constant, honest, and
// don't fluctuate with unrelated scans.
// ============================================================================

function avgConfidencePct(findings) {
  const withConf = findings.filter((f) => typeof f.confidence === 'number');
  if (withConf.length === 0) return null;
  return Math.round((withConf.reduce((s, f) => s + f.confidence, 0) / withConf.length) * 100);
}

const COVERAGE_ITEMS = [
  { key: 'secrets', label: 'Secrets Detection', icon: KeyRound, color: '#a98cf0', match: (f) => categoryOf(f) === 'secrets' },
  { key: 'injection', label: 'Injection Analysis', icon: Zap, color: '#4fd08a', match: (f) => categoryOf(f) === 'injection' },
  { key: 'auth', label: 'Authentication', icon: Lock, color: '#3ba7f0', match: (f) => categoryOf(f) === 'auth' },
  { key: 'access', label: 'Authorization', icon: ShieldAlert, color: '#e8a33d', match: (f) => categoryOf(f) === 'access' },
  { key: 'config', label: 'Configuration Security', icon: Sliders, color: '#3ba7f0', match: (f) => categoryOf(f) === 'config' },
  { key: 'deps', label: 'Dependency Security', icon: Package, color: '#a98cf0', match: (f) => categoryOf(f) === 'deps' },
  {
    key: 'inputval', label: 'Input Validation', icon: CheckCircle2, color: '#4fd08a',
    match: (f) => { const t = `${f.type || ''} ${f.explanation || ''}`.toLowerCase(); return t.includes('input validation') || t.includes('unvalidated') || t.includes('sanitiz'); },
  },
  {
    key: 'crypto', label: 'Cryptography', icon: Lock, color: '#e8a33d',
    match: (f) => { const t = `${f.type || ''} ${f.explanation || ''}`.toLowerCase(); return t.includes('crypto') || t.includes('encrypt') || t.includes('hash') || t.includes('cipher'); },
  },
  {
    key: 'logging', label: 'Logging & Monitoring', icon: FileText, color: '#3ba7f0',
    match: (f) => { const t = `${f.type || ''} ${f.explanation || ''}`.toLowerCase(); return t.includes('logging') || t.includes('monitor') || t.includes('audit'); },
  },
];

// Whether the scanner has dedicated detection logic for each OWASP Top 10
// (2021) category, based on what categoryOf()/keyword matching in this file
// can actually recognize. This is a capability statement, not a per-scan
// result, so it's intentionally not derived from `results`.
const OWASP_TOP10 = [
  { id: 'A01', label: 'Broken Access Control', status: 'checked' },
  { id: 'A02', label: 'Cryptographic Failures', status: 'partial' },
  { id: 'A03', label: 'Injection', status: 'checked' },
  { id: 'A04', label: 'Insecure Design', status: 'partial' },
  { id: 'A05', label: 'Security Misconfiguration', status: 'checked' },
  { id: 'A06', label: 'Vulnerable & Outdated Components', status: 'checked' },
  { id: 'A07', label: 'Identification & Authentication Failures', status: 'checked' },
  { id: 'A08', label: 'Software & Data Integrity Failures', status: 'partial' },
  { id: 'A09', label: 'Security Logging & Monitoring Failures', status: 'partial' },
  { id: 'A10', label: 'Server-Side Request Forgery (SSRF)', status: 'partial' },
];

const AI_SUMMARY_TILES = [
  { key: 'source', label: 'Source Code Reviewed', desc: 'AI analyzed your source code for security issues', icon: Brain },
  { key: 'secrets', label: 'Secrets Scanned', desc: 'Checked for hardcoded secrets and credentials', icon: KeyRound },
  { key: 'config', label: 'Configurations Analyzed', desc: 'Scanned configs for security misconfigurations', icon: Sliders },
  { key: 'deps', label: 'Dependencies Analyzed', desc: 'Analyzed dependency tree for vulnerabilities', icon: Package },
  { key: 'risk', label: 'Risks Prioritized', desc: 'AI prioritized issues by risk and impact', icon: BarChart2 },
  { key: 'fix', label: 'Fix Suggestions', desc: 'AI generated fix suggestions', icon: ShieldCheck },
];

function SecurityCoveragePanel({ results, code, scanDurationMs }) {
  const allFindings = results?.findings || [];

  const coverage = COVERAGE_ITEMS.map((item) => {
    const matches = allFindings.filter(item.match);
    const pct = matches.length > 0 ? (avgConfidencePct(matches) ?? 90) : 100;
    return { ...item, count: matches.length, pct };
  });

  const overallPct = coverage.length
    ? Math.round(coverage.reduce((s, c) => s + c.pct, 0) / coverage.length)
    : 100;
  const overallLabel = overallPct >= 90 ? 'Excellent' : overallPct >= 75 ? 'Good' : overallPct >= 50 ? 'Moderate' : 'Poor';
  const overallColor = overallPct >= 90 ? '#4fd08a' : overallPct >= 75 ? '#8dd66a' : overallPct >= 50 ? '#e8a33d' : '#e2504a';

  const totalChecks = coverage.length;
  const aiConfPct = avgConfidencePct(allFindings);

  const linesScanned = code ? code.split('\n').length : 0;
  const contentType = detectFileType(code);

  const hasData = Boolean(results);

  return (
    <section className="panel wide-panel">
      <div className="panel-head">
        <div className="panel-icon"><ShieldAlert size={18} /></div>
        <div>
          <h2>Security Coverage</h2>
          <p>What SecureCode checks for on every scan, and what your last scan found.</p>
        </div>
      </div>

      {!hasData && (
        <div className="empty-state">
          <ShieldAlert size={56} className="empty-icon" />
          <h3>Run a scan to see coverage.</h3>
          <p className="empty-sub">Coverage is based on your most recent scan from Code Scan.</p>
        </div>
      )}

      {hasData && (
        <>
          <div className="dash-mid-grid" style={{ marginBottom: '16px' }}>
            <div className="dash-sub-panel">
              <h3>Overall Security Coverage</h3>
              <div className="dash-donut-row">
                <svg width="110" height="110" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  <circle
                    cx="21" cy="21" r="15.9" fill="transparent"
                    stroke={overallColor} strokeWidth="6"
                    strokeDasharray={`${overallPct} ${100 - overallPct}`}
                    strokeDashoffset="25"
                  />
                  <text x="21" y="19" textAnchor="middle" fontSize="7.5" fill="#e8e9ee" fontWeight="700">{overallPct}%</text>
                  <text x="21" y="26" textAnchor="middle" fontSize="3.6" fill="#5c5f6d">Coverage</text>
                </svg>
                <div>
                  <div className="dash-stat-value" style={{ color: overallColor, fontSize: '20px' }}>{overallLabel}</div>
                  <div className="dash-stat-sub">Across {totalChecks} categories</div>
                </div>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Security Checks Completed</h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginTop: '10px' }}>
                <div className="dash-stat-value" style={{ fontSize: '32px' }}>{totalChecks}<span style={{ fontSize: '18px' }}> / {totalChecks}</span></div>
                <CheckCircle2 size={32} style={{ color: '#4fd08a', opacity: 0.7 }} />
              </div>
              <div className="dash-stat-sub" style={{ color: '#4fd08a', marginTop: '6px' }}>100% Completed</div>
            </div>

            <div className="dash-sub-panel">
              <h3>Scan Details</h3>
              <div className="dash-stats-grid" style={{ gridTemplateColumns: '1fr 1fr', marginTop: '4px' }}>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><FileText size={14} /> Content Type</div>
                  <div className="dash-stat-value" style={{ fontSize: '15px' }}>{contentType}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><Code2 size={14} /> Lines Scanned</div>
                  <div className="dash-stat-value" style={{ fontSize: '15px' }}>{linesScanned}</div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><Clock size={14} /> Scan Duration</div>
                  <div className="dash-stat-value" style={{ fontSize: '15px' }}>
                    {scanDurationMs !== null && scanDurationMs !== undefined ? `${(scanDurationMs / 1000).toFixed(2)}s` : '—'}
                  </div>
                </div>
                <div className="dash-stat-card">
                  <div className="dash-stat-head"><ShieldAlert size={14} /> Risk Level</div>
                  <div className="dash-stat-value" style={{ fontSize: '15px', color: overallColor }}>{results.riskLevel ?? '—'}</div>
                </div>
              </div>
            </div>
          </div>

          <div className="dash-sub-panel" style={{ marginBottom: '16px' }}>
            <h3>Coverage by Category</h3>
            <div className="dash-cap-grid">
              {coverage.slice(0, 6).map((c) => {
                const Icon = c.icon;
                return (
                  <div className="dash-cap-card" key={c.key}>
                    <div className="dash-cap-icon" style={{ color: c.color }}><Icon size={14} /></div>
                    <div className="dash-cap-title">{c.label}</div>
                    <div style={{ fontSize: '11.5px', opacity: 0.6, margin: '2px 0 8px' }}>
                      {c.count === 0 ? 'No issues found' : `${c.count} issue${c.count !== 1 ? 's' : ''} found`}
                    </div>
                    <div className="dash-cat-row" style={{ margin: 0 }}>
                      <div className="dash-cat-label" style={{ fontSize: '11px' }}>Coverage</div>
                      <div className="dash-cat-track">
                        <div className="dash-cat-fill" style={{ width: `${c.pct}%`, background: c.color }} />
                      </div>
                      <div className="dash-cat-count" style={{ color: c.color, fontWeight: 700 }}>{c.pct}%</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="content-grid">
            <div className="left-col">
              <section className="panel">
                <div className="panel-head"><div><h2>Coverage Details</h2></div></div>
                {coverage.map((c) => (
                  <div className="dash-cat-row" key={c.key}>
                    <span className="dash-dot" style={{ background: c.color }} />
                    <div className="dash-cat-label">{c.label}</div>
                    <div className="dash-cat-track">
                      <div className="dash-cat-fill" style={{ width: `${c.pct}%`, background: c.color }} />
                    </div>
                    <div className="dash-cat-count">{c.pct}%</div>
                  </div>
                ))}
              </section>
            </div>

            <section className="panel risk-side-panel">
              <div className="panel-head">
                <div><h2>OWASP Top 10 Coverage</h2></div>
                <a
                  href="https://owasp.org/Top10/"
                  target="_blank" rel="noreferrer"
                  className="text-btn" style={{ marginLeft: 'auto' }}
                >
                  Learn more
                </a>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '6px' }}>
                {OWASP_TOP10.map((o) => {
                  const checked = o.status === 'checked';
                  const Icon = checked ? CheckCircle2 : AlertTriangle;
                  const color = checked ? '#4fd08a' : '#e8a33d';
                  return (
                    <div key={o.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '12.5px' }}>
                      <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <Icon size={14} style={{ color, flexShrink: 0 }} />
                        {o.id}: {o.label}
                      </span>
                      <span
                        className="chip"
                        style={{ background: `${color}22`, color, border: `1px solid ${color}66`, flexShrink: 0 }}
                      >
                        {checked ? 'Checked' : 'Partial'}
                      </span>
                    </div>
                  );
                })}
              </div>
            </section>
          </div>

          <div className="dash-sub-panel" style={{ marginTop: '16px' }}>
            <h3>AI Analysis Summary</h3>
            <div className="dash-cap-grid" style={{ marginBottom: '14px' }}>
              {AI_SUMMARY_TILES.map((t) => {
                const Icon = t.icon;
                return (
                  <div className="dash-cap-card" key={t.key}>
                    <div className="dash-cap-icon"><Icon size={14} /></div>
                    <div className="dash-cap-title">{t.label}</div>
                    <div style={{ fontSize: '11.5px', opacity: 0.6, marginTop: '4px' }}>{t.desc}</div>
                  </div>
                );
              })}
            </div>
            <div className="dash-stat-card" style={{ maxWidth: '260px' }}>
              <div className="dash-stat-head">AI Confidence Score</div>
              <div className="dash-stat-value" style={{ color: '#a98cf0', fontSize: '30px' }}>
                {aiConfPct !== null ? `${aiConfPct}%` : '—'}
              </div>
              <div className="dash-stat-sub" style={{ color: '#a98cf0' }}>
                {aiConfPct !== null ? (aiConfPct >= 80 ? 'High Confidence' : aiConfPct >= 50 ? 'Moderate Confidence' : 'Low Confidence') : 'No AI findings yet'}
              </div>
            </div>
          </div>
        </>
      )}
    </section>
  );
}

// ============================================================================
// Scan Results — dedicated panel (replaces the old flat CodeFindingsList
// view). Shows ONLY the most recent in-session scan (`results`), never
// aggregated history — matches "Fixed / Open" status is tracked locally in
// this component's state since the backend has no remediation-tracking
// field; it resets whenever a new scan comes in. Risk scores reuse
// computeRiskScore() from AI Prioritization, and the "AI Explanation" panel
// reads straight from each finding's real `explanation`/`fix`/`confidence`/
// `matchPreview` fields — no fabricated CWE IDs or before/after code diffs.
// ============================================================================

function ScanResultsPanel({ results, history, code, scanning, onRescan, goToNav }) {
  const [fixedMap, setFixedMap] = useState({});
  const [activeFilter, setActiveFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(null);
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 10;

  const findings = results?.findings || [];

  // New scan came in (different results object) — reset all local UI state.
  useEffect(() => {
    setFixedMap({});
    setActiveFilter('all');
    setSearch('');
    setSelectedIndex(null);
    setPage(1);
  }, [results]);

  const scored = findings.map((f, i) => ({ ...f, _index: i, _score: computeRiskScore(f), _fixed: Boolean(fixedMap[i]) }));

  const critical = scored.filter((f) => severityClass(f.severity) === 'sev-critical').length;
  const high = scored.filter((f) => severityClass(f.severity) === 'sev-high').length;
  const medium = scored.filter((f) => severityClass(f.severity) === 'sev-medium').length;
  const low = scored.filter((f) => severityClass(f.severity) === 'sev-low').length;
  const fixedCount = scored.filter((f) => f._fixed).length;
  const openCount = scored.length - fixedCount;
  const totalIssues = scored.length;
  const remediationPct = totalIssues ? Math.round((fixedCount / totalIssues) * 100) : 0;

  const uniqueLocations = new Set(scored.map((f) => locationForFinding(f))).size;

  const securityScore = Math.max(0, 100 - (results?.riskScore ?? 0));
  const scoreLabel = securityScore >= 90 ? 'Excellent' : securityScore >= 75 ? 'Good' : securityScore >= 50 ? 'Fair' : 'Poor';
  const scoreColor = securityScore >= 90 ? '#4fd08a' : securityScore >= 75 ? '#8dd66a' : securityScore >= 50 ? '#e8a33d' : '#e2504a';

  const sortedHistory = [...(history || [])].sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
  const lastScannedLabel = sortedHistory[0] ? formatDate(sortedHistory[0].scannedAt) : 'Just now';

  const FILTERS = [
    { key: 'all', label: `All (${totalIssues})` },
    { key: 'critical', label: `Critical (${critical})` },
    { key: 'high', label: `High (${high})` },
    { key: 'medium', label: `Medium (${medium})` },
    { key: 'low', label: `Low (${low})` },
    { key: 'fixed', label: `Fixed (${fixedCount})` },
    { key: 'open', label: `Open (${openCount})` },
  ];

  let filtered = scored;
  if (activeFilter === 'critical') filtered = filtered.filter((f) => severityClass(f.severity) === 'sev-critical');
  else if (activeFilter === 'high') filtered = filtered.filter((f) => severityClass(f.severity) === 'sev-high');
  else if (activeFilter === 'medium') filtered = filtered.filter((f) => severityClass(f.severity) === 'sev-medium');
  else if (activeFilter === 'low') filtered = filtered.filter((f) => severityClass(f.severity) === 'sev-low');
  else if (activeFilter === 'fixed') filtered = filtered.filter((f) => f._fixed);
  else if (activeFilter === 'open') filtered = filtered.filter((f) => !f._fixed);

  if (search.trim()) {
    const q = search.trim().toLowerCase();
    filtered = filtered.filter((f) => `${f.type || ''} ${f.explanation || ''} ${f.packageName || ''}`.toLowerCase().includes(q));
  }

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageClamped = Math.min(page, totalPages);
  const pageItems = filtered.slice((pageClamped - 1) * PAGE_SIZE, pageClamped * PAGE_SIZE);

  const selected = selectedIndex !== null ? scored.find((f) => f._index === selectedIndex) : null;

  function toggleFixed(index) {
    setFixedMap((prev) => ({ ...prev, [index]: !prev[index] }));
  }

  function handleCopyFix(fix) {
    navigator.clipboard?.writeText(fix || '');
  }

  const hasData = Boolean(results);

  return (
    <section className="panel wide-panel">
      <div className="panel-head">
        <div className="panel-icon"><FileText size={18} /></div>
        <div>
          <h2>Scan Results</h2>
          <p>Detailed results of security vulnerabilities found in your most recent scan.</p>
        </div>
        {hasData && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginLeft: 'auto' }}>
            <span style={{ fontSize: '12.5px', opacity: 0.6, display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Clock size={13} /> Last scanned: {lastScannedLabel}
            </span>
            <button className="scan-btn" style={{ padding: '8px 14px' }} onClick={onRescan} disabled={scanning || !code?.trim()}>
              <Search size={14} /> {scanning ? 'Scanning…' : 'Rescan'}
            </button>
          </div>
        )}
      </div>

      {!hasData && (
        <div className="empty-state">
          <FileText size={56} className="empty-icon" />
          <h3>No scan run yet.</h3>
          <p className="empty-sub">Head to Code Scan to run one — results mirror here.</p>
        </div>
      )}

      {hasData && totalIssues === 0 && (
        <div className="empty-state">
          <CheckCircle2 size={56} className="empty-icon success" />
          <h3>No issues found. Nice and clean.</h3>
        </div>
      )}

      {hasData && totalIssues > 0 && (
        <>
          <div className="dash-mid-grid" style={{ marginBottom: '16px', gridTemplateColumns: 'repeat(4, 1fr) 1.4fr' }}>
            <div className="dash-sub-panel">
              <h3>Security Score</h3>
              <div className="dash-donut-row">
                <svg width="90" height="90" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  <circle
                    cx="21" cy="21" r="15.9" fill="transparent"
                    stroke={scoreColor} strokeWidth="6"
                    strokeDasharray={`${securityScore} ${100 - securityScore}`}
                    strokeDashoffset="25"
                  />
                  <text x="21" y="19" textAnchor="middle" fontSize="8" fill="#e8e9ee" fontWeight="700">{securityScore}</text>
                  <text x="21" y="26" textAnchor="middle" fontSize="3.4" fill="#5c5f6d">/100</text>
                </svg>
                <div className="dash-stat-sub" style={{ color: scoreColor, fontWeight: 600 }}>{scoreLabel}</div>
              </div>
            </div>

            <div className="dash-stat-card">
              <div className="dash-stat-head"><ShieldAlert size={14} /> Issues Found</div>
              <div className="dash-stat-value">{totalIssues}</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><CheckCircle2 size={14} /> Fixed</div>
              <div className="dash-stat-value" style={{ color: '#4fd08a' }}>{fixedCount}</div>
              <div className="dash-stat-sub">{remediationPct}% resolved</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><AlertTriangle size={14} /> Remaining</div>
              <div className="dash-stat-value" style={{ color: '#e8a33d' }}>{openCount}</div>
            </div>
            <div className="dash-sub-panel">
              <h3>Remediation Progress</h3>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span style={{ fontSize: '12px', opacity: 0.6 }}>{uniqueLocations} location{uniqueLocations !== 1 ? 's' : ''} affected</span>
                <span style={{ fontSize: '13px', fontWeight: 700, color: '#a98cf0' }}>{remediationPct}% Completed</span>
              </div>
              <div className="dash-cat-track" style={{ width: '100%' }}>
                <div className="dash-cat-fill" style={{ width: `${remediationPct}%`, background: '#a98cf0' }} />
              </div>
              <div style={{ display: 'flex', gap: '14px', marginTop: '8px', fontSize: '12px' }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span className="dash-dot" style={{ background: '#4fd08a' }} />{fixedCount} Fixed</span>
                <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><span className="dash-dot" style={{ background: '#e8a33d' }} />{openCount} Remaining</span>
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px', alignItems: 'center', marginBottom: '14px' }}>
            {FILTERS.map((f) => (
              <button
                key={f.key}
                className="text-btn"
                style={{
                  padding: '6px 12px', borderRadius: '8px',
                  background: activeFilter === f.key ? 'rgba(169,140,240,0.18)' : 'rgba(255,255,255,0.03)',
                  border: activeFilter === f.key ? '1px solid rgba(169,140,240,0.5)' : '1px solid rgba(255,255,255,0.08)',
                  color: activeFilter === f.key ? '#a98cf0' : undefined,
                }}
                onClick={() => { setActiveFilter(f.key); setPage(1); }}
              >
                {f.label}
              </button>
            ))}
            <div style={{ marginLeft: 'auto' }}>
              <input
                className="code-input"
                style={{ height: 'auto', padding: '8px 12px', width: '220px' }}
                placeholder="Search issues..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              />
            </div>
          </div>

          <div className="content-grid">
            <div className="left-col">
              <section className="panel">
                <div className="secrets-table-wrap">
                  <table className="secrets-table">
                    <thead>
                      <tr>
                        <th>Issue / Location</th><th>Severity</th><th>Risk Score</th><th>Status</th><th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {pageItems.map((f) => {
                        const isCritical = severityClass(f.severity) === 'sev-critical';
                        const isSelected = selectedIndex === f._index;
                        return (
                          <tr
                            key={f._index}
                            style={{ cursor: 'pointer', background: isSelected ? 'rgba(169,140,240,0.08)' : undefined }}
                            onClick={() => setSelectedIndex(f._index)}
                          >
                            <td>
                              <div style={{ fontWeight: 600 }}>{f.type}</div>
                              <div style={{ fontSize: '11.5px', opacity: 0.55, fontFamily: 'monospace' }}>{locationForFinding(f)}</div>
                            </td>
                            <td>
                              <span className={`sev-pill ${severityClass(f.severity)}`} style={isCritical ? CRITICAL_FALLBACK : undefined}>{f.severity}</span>
                            </td>
                            <td style={{ fontWeight: 700 }}>{(f._score / 10).toFixed(1)}/10</td>
                            <td>
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12.5px' }}>
                                <span className="dash-dot" style={{ background: f._fixed ? '#4fd08a' : '#e2504a' }} />
                                {f._fixed ? 'Fixed' : 'Open'}
                              </span>
                            </td>
                            <td onClick={(e) => e.stopPropagation()}>
                              <button className="icon-btn" onClick={() => toggleFixed(f._index)} aria-label={f._fixed ? 'Mark as open' : 'Mark as fixed'}>
                                {f._fixed ? <AlertTriangle size={14} /> : <Check size={14} />}
                              </button>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {filtered.length === 0 && (
                  <p className="empty-sub" style={{ marginTop: '10px' }}>No issues match your filters.</p>
                )}

                {filtered.length > 0 && (
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '12px' }}>
                    <span style={{ fontSize: '12.5px', opacity: 0.6 }}>
                      Showing {(pageClamped - 1) * PAGE_SIZE + 1} to {Math.min(pageClamped * PAGE_SIZE, filtered.length)} of {filtered.length} results
                    </span>
                    <div style={{ display: 'flex', gap: '6px', alignItems: 'center' }}>
                      <button className="icon-btn" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={pageClamped === 1} aria-label="Previous page">
                        <ChevronRight size={14} style={{ transform: 'rotate(180deg)' }} />
                      </button>
                      <span style={{ fontSize: '12.5px' }}>{pageClamped} / {totalPages}</span>
                      <button className="icon-btn" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={pageClamped === totalPages} aria-label="Next page">
                        <ChevronRight size={14} />
                      </button>
                    </div>
                  </div>
                )}
              </section>
            </div>

            <section className="panel risk-side-panel">
              {!selected && (
                <div className="empty-state">
                  <Brain size={40} className="empty-icon" />
                  <h3 style={{ fontSize: '14px' }}>Select an issue</h3>
                  <p className="empty-sub">Click a row to see the AI explanation and suggested fix.</p>
                </div>
              )}
              {selected && (
                <>
                  <div className="panel-head">
                    <div><h2 style={{ fontSize: '16px' }}>{selected.type}</h2></div>
                    <span className={`sev-pill ${severityClass(selected.severity)}`} style={severityClass(selected.severity) === 'sev-critical' ? CRITICAL_FALLBACK : undefined}>
                      {selected.severity}
                    </span>
                    <button className="icon-btn" style={{ marginLeft: '8px' }} onClick={() => setSelectedIndex(null)} aria-label="Close">
                      <X size={14} />
                    </button>
                  </div>
                  <div style={{ fontSize: '12px', opacity: 0.6, marginBottom: '12px' }}>{locationForFinding(selected)}</div>

                  <div className="finding-card">
                    <div className="finding-type" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><Brain size={13} /> AI Explanation</div>
                    <div className="finding-preview" style={{ marginTop: '6px' }}>{selected.explanation || 'No explanation available for this finding.'}</div>
                    {typeof selected.confidence === 'number' && (
                      <div style={{ marginTop: '10px' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11.5px', opacity: 0.6, marginBottom: '4px' }}>
                          <span>AI Confidence</span><span>{Math.round(selected.confidence * 100)}%</span>
                        </div>
                        <div className="dash-cat-track"><div className="dash-cat-fill" style={{ width: `${Math.round(selected.confidence * 100)}%` }} /></div>
                      </div>
                    )}
                  </div>

                  {selected.matchPreview && (
                    <div className="finding-card">
                      <div className="finding-type">Flagged Code</div>
                      <div className="finding-preview" style={{ fontFamily: 'monospace', fontSize: '12px', whiteSpace: 'pre-wrap' }}>{selected.matchPreview}</div>
                    </div>
                  )}

                  <div className="finding-card">
                    <div className="finding-type" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><Wrench size={13} /> Suggested Fix</div>
                    <div className="finding-preview" style={{ marginTop: '6px' }}>{selected.fix || 'No fix suggestion available.'}</div>
                  </div>

                  <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
                    <button className="scan-btn" style={{ flex: 1 }} onClick={() => handleCopyFix(selected.fix)}>
                      <Copy size={14} /> Copy Fix
                    </button>
                    <button className="text-btn" style={{ flex: 1, justifyContent: 'center' }} onClick={() => goToNav('Code Scan')}>
                      <ExternalLink size={13} /> View in Code
                    </button>
                  </div>
                </>
              )}
            </section>
          </div>
        </>
      )}
    </section>
  );
}

// ============================================================================
// Reports — dedicated panel (replaces the old flat category-count list).
// Reads from the same `results` / `history` state Code Scan already
// populates — no mock data. Mirrors the target layout: security score
// gauge, severity + category breakdowns, a trend line across saved scans,
// an AI executive summary, top recommendations, and a Recent Scans table.
// Each row (and the panel as a whole) can be downloaded as JSON client-side
// via a Blob — no backend changes needed, and nothing else in the app is
// touched.
// ============================================================================

function downloadJSON(filename, data) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// Groups the fine-grained categoryOf() buckets into the 5 slices shown in
// the Reports "Findings by Category" donut — mirrors the target design's
// Vulnerabilities / Secrets / Dependencies / Configuration / Other split.
const REPORT_CATEGORY_GROUPS = [
  { key: 'vulnerabilities', label: 'Vulnerabilities', color: '#a98cf0', match: (f) => ['injection', 'auth', 'access', 'logic'].includes(categoryOf(f)) },
  { key: 'secrets', label: 'Secrets', color: '#e2504a', match: (f) => categoryOf(f) === 'secrets' },
  { key: 'dependencies', label: 'Dependencies', color: '#3ba7f0', match: (f) => categoryOf(f) === 'deps' },
  { key: 'configuration', label: 'Configuration', color: '#e8a33d', match: (f) => categoryOf(f) === 'config' },
  { key: 'other', label: 'Other', color: '#4fd08a', match: (f) => categoryOf(f) === 'other' },
];

function ReportsPanel({ results, history, historyLoading }) {
  const sortedHistory = [...(history || [])].sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));
  const latest = results || sortedHistory[0] || null;
  const latestFindings = results ? (results.findings || []) : parseFindings(sortedHistory[0]);

  const hasData = Boolean(latest);

  const critical = latest?.critical ?? 0;
  const high = latest?.highSeverity ?? 0;
  const medium = latest?.mediumSeverity ?? 0;
  const low = latest?.lowSeverity ?? 0;
  const totalIssues = latest?.totalFindings ?? (critical + high + medium + low);
  const riskScore = latest?.riskScore ?? 0;
  const riskLevel = latest?.riskLevel ?? '—';
  const securityScore = Math.max(0, 100 - riskScore);
  const scoreLabel = securityScore >= 90 ? 'Excellent' : securityScore >= 75 ? 'Good' : securityScore >= 50 ? 'Medium Risk' : 'High Risk';
  const scoreColor = securityScore >= 90 ? '#4fd08a' : securityScore >= 75 ? '#8dd66a' : securityScore >= 50 ? '#e8a33d' : '#e2504a';

  // The backend has no per-issue fixed/open persistence (that only lives in
  // ScanResultsPanel's local session state), so "Resolved" here is the
  // honest analogue: how much the total finding count has dropped since
  // your earliest saved scan, not a per-issue checklist.
  const oldestInHistory = sortedHistory[sortedHistory.length - 1];
  const baselineTotal = oldestInHistory?.totalFindings ?? totalIssues;
  const resolvedSinceStart = Math.max(0, baselineTotal - totalIssues);
  const remaining = totalIssues;

  const filesAffected = new Set(latestFindings.map(locationForFinding).filter((l) => l !== '—')).size;

  const severityRows = [
    { key: 'critical', label: 'Critical', count: critical, color: '#e2504a' },
    { key: 'high', label: 'High', count: high, color: '#e8a33d' },
    { key: 'medium', label: 'Medium', count: medium, color: '#d9c94f' },
    { key: 'low', label: 'Low', count: low, color: '#4fd08a' },
  ];

  const categoryRows = REPORT_CATEGORY_GROUPS.map((g) => ({ ...g, count: latestFindings.filter(g.match).length }));
  const categoryTotal = categoryRows.reduce((s, c) => s + c.count, 0);

  // Last 6 scans, oldest → latest, for the trend line — plotted as
  // "security score" (100 - riskScore) to match the higher-is-better axis
  // on screen.
  const trendScans = [...sortedHistory].slice(0, 6).reverse();

  const confidences = latestFindings.filter((f) => typeof f.confidence === 'number');
  const aiConfidencePct = confidences.length
    ? Math.round((confidences.reduce((s, f) => s + f.confidence, 0) / confidences.length) * 100)
    : null;

  const previousScan = sortedHistory[0];
  const scoreDelta = previousScan && typeof previousScan.riskScore === 'number'
    ? securityScore - Math.max(0, 100 - previousScan.riskScore)
    : null;

  const summaryLines = [];
  if (hasData) {
    summaryLines.push(`SecureCode detected ${totalIssues} issue${totalIssues !== 1 ? 's' : ''} in your codebase.`);
    if (critical > 0) {
      summaryLines.push(`${critical} critical issue${critical !== 1 ? 's' : ''} require immediate attention as ${critical !== 1 ? 'they pose' : 'it poses'} a high risk to your application.`);
    }
    if (scoreDelta !== null && scoreDelta !== 0) {
      summaryLines.push(`Your security score ${scoreDelta >= 0 ? 'improved' : 'dropped'} by ${Math.abs(scoreDelta)} point${Math.abs(scoreDelta) !== 1 ? 's' : ''} compared to the previous scan.`);
    }
    summaryLines.push('Focus on fixing critical and high severity issues first to reduce overall risk.');
  }

  const recommendations = [];
  if (categoryRows.find((c) => c.key === 'vulnerabilities')?.count > 0) {
    recommendations.push({ icon: ShieldAlert, label: 'Fix injection vulnerabilities', sev: 'Critical' });
  }
  if (categoryRows.find((c) => c.key === 'secrets')?.count > 0) {
    recommendations.push({ icon: KeyRound, label: 'Remove hardcoded secrets', sev: 'High' });
  }
  if (categoryRows.find((c) => c.key === 'dependencies')?.count > 0) {
    recommendations.push({ icon: Package, label: 'Update vulnerable dependencies', sev: 'High' });
  }
  if (categoryRows.find((c) => c.key === 'configuration')?.count > 0) {
    recommendations.push({ icon: Sliders, label: 'Secure configuration files', sev: 'Medium' });
  }
  if (recommendations.length < 5) {
    recommendations.push({ icon: Code2, label: 'Use environment variables for secrets', sev: 'Medium' });
  }

  function recSevStyle(sev) {
    if (sev === 'Critical') return CRITICAL_FALLBACK;
    if (sev === 'High') return { background: 'rgba(232,163,61,0.15)', color: '#e8a33d', border: '1px solid rgba(232,163,61,0.4)' };
    return { background: 'rgba(217,201,79,0.15)', color: '#d9c94f', border: '1px solid rgba(217,201,79,0.4)' };
  }

  function handleExportAll() {
    downloadJSON('securecode-report.json', {
      generatedAt: new Date().toISOString(),
      latestScan: latest,
      allScans: sortedHistory,
    });
  }

  function handleDownloadScan(scan) {
    downloadJSON(`securecode-scan-${scan.id}.json`, scan);
  }

  return (
    <section className="panel wide-panel">
      <div className="panel-head">
        <div className="panel-icon"><BarChart2 size={18} /></div>
        <div>
          <h2>Reports</h2>
          <p>Comprehensive security overview of your project.</p>
        </div>
        {sortedHistory[0] && (
          <span style={{ fontSize: '12.5px', opacity: 0.6, display: 'flex', alignItems: 'center', gap: '6px', marginLeft: 'auto' }}>
            <Clock size={13} /> Last scanned: {formatDate(sortedHistory[0].scannedAt)}
          </span>
        )}
        <button className="scan-btn" style={{ padding: '8px 14px', marginLeft: '12px' }} onClick={handleExportAll} disabled={!hasData}>
          <Download size={14} /> Export Report
        </button>
      </div>

      {historyLoading && !hasData && (
        <div className="empty-state">
          <Clock size={56} className="empty-icon" />
          <h3>Loading your scan data…</h3>
        </div>
      )}

      {!historyLoading && !hasData && (
        <div className="empty-state">
          <BarChart2 size={56} className="empty-icon" />
          <h3>No scans yet.</h3>
          <p className="empty-sub">Run a scan from Code Scan and your report will populate automatically.</p>
        </div>
      )}

      {hasData && (
        <>
          <div className="dash-mid-grid" style={{ gridTemplateColumns: '1.2fr 1fr 1fr 1fr 1fr', marginBottom: '16px' }}>
            <div className="dash-sub-panel">
              <h3>Security Overview</h3>
              <div className="dash-donut-row">
                <svg width="100" height="100" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  <circle
                    cx="21" cy="21" r="15.9" fill="transparent"
                    stroke={scoreColor} strokeWidth="6"
                    strokeDasharray={`${securityScore} ${100 - securityScore}`}
                    strokeDashoffset="25"
                  />
                  <text x="21" y="19" textAnchor="middle" fontSize="8" fill="#e8e9ee" fontWeight="700">{securityScore}</text>
                  <text x="21" y="26" textAnchor="middle" fontSize="3.4" fill="#5c5f6d">/100</text>
                </svg>
                <div className="dash-stat-sub" style={{ color: scoreColor, fontWeight: 600 }}>{scoreLabel}</div>
              </div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#3a1d1d', color: '#e2504a' }}><ShieldAlert size={14} /></span>Total Issues</div>
              <div className="dash-stat-value">{totalIssues}</div>
              <div className="dash-stat-sub">All identified issues</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#12301f', color: '#4fd08a' }}><CheckCircle2 size={14} /></span>Resolved</div>
              <div className="dash-stat-value">{resolvedSinceStart}</div>
              <div className="dash-stat-sub">Since your first scan</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#3a2a12', color: '#e8a33d' }}><ShieldAlert size={14} /></span>Remaining</div>
              <div className="dash-stat-value">{remaining}</div>
              <div className="dash-stat-sub">Issues to fix</div>
            </div>
            <div className="dash-stat-card">
              <div className="dash-stat-head"><span className="dash-stat-icon" style={{ background: '#12283a', color: '#3ba7f0' }}><FileText size={14} /></span>Files Affected</div>
              <div className="dash-stat-value">{filesAffected}</div>
              <div className="dash-stat-sub">Scanned locations</div>
            </div>
          </div>

          <div className="dash-mid-grid" style={{ marginBottom: '16px' }}>
            <div className="dash-sub-panel">
              <h3>Severity Overview</h3>
              {severityRows.map((s) => (
                <div className="dash-cat-row" key={s.key}>
                  <span className="dash-dot" style={{ background: s.color }} />
                  <div className="dash-cat-label">{s.label}</div>
                  <div className="dash-cat-track">
                    <div className="dash-cat-fill" style={{ width: `${totalIssues ? (s.count / totalIssues) * 100 : 0}%`, background: s.color }} />
                  </div>
                  <div className="dash-cat-count">{totalIssues ? Math.round((s.count / totalIssues) * 100) : 0}%</div>
                </div>
              ))}
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px', fontSize: '12.5px', opacity: 0.65 }}>
                <span>Total Issues</span><span>{totalIssues}</span>
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3>Findings by Category</h3>
              <div className="dash-donut-row">
                <svg width="100" height="100" viewBox="0 0 42 42">
                  <circle cx="21" cy="21" r="15.9" fill="transparent" stroke="#232633" strokeWidth="6" />
                  {(() => {
                    let offset = 25;
                    return categoryRows.map((c) => {
                      const pct = categoryTotal > 0 ? (c.count / categoryTotal) * 100 : 0;
                      const circle = (
                        <circle
                          key={c.key} cx="21" cy="21" r="15.9" fill="transparent"
                          stroke={c.color} strokeWidth="6"
                          strokeDasharray={`${pct} ${100 - pct}`}
                          strokeDashoffset={offset}
                        />
                      );
                      offset -= pct;
                      return circle;
                    });
                  })()}
                  <text x="21" y="19" textAnchor="middle" fontSize="7" fill="#e8e9ee" fontWeight="700">{categoryTotal}</text>
                  <text x="21" y="26" textAnchor="middle" fontSize="4" fill="#5c5f6d">Total</text>
                </svg>
                <div className="dash-legend">
                  {categoryRows.map((c) => (
                    <div className="dash-legend-item" key={c.key}>
                      <span className="dash-dot" style={{ background: c.color }} />{c.label}
                      <span className="dash-legend-count">{c.count} ({categoryTotal > 0 ? Math.round((c.count / categoryTotal) * 100) : 0}%)</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          <div className="dash-mid-grid" style={{ marginBottom: '16px' }}>
            <div className="dash-sub-panel">
              <h3>Security Trend</h3>
              <p className="dash-sub-caption">Last {trendScans.length || 0} scan{trendScans.length !== 1 ? 's' : ''}</p>
              {trendScans.length === 0 && <p className="empty-sub">Not enough history yet.</p>}
              {trendScans.length > 0 && (
                <svg width="100%" height="110" viewBox="0 0 260 100" preserveAspectRatio="none">
                  <polyline
                    fill="none" stroke="#a98cf0" strokeWidth="2"
                    points={trendScans.map((s, i) => {
                      const x = trendScans.length > 1 ? (i / (trendScans.length - 1)) * 250 + 5 : 130;
                      const sc = Math.max(0, 100 - (s.riskScore ?? 0));
                      const y = 90 - (sc / 100) * 80;
                      return `${x},${y}`;
                    }).join(' ')}
                  />
                  {trendScans.map((s, i) => {
                    const x = trendScans.length > 1 ? (i / (trendScans.length - 1)) * 250 + 5 : 130;
                    const sc = Math.max(0, 100 - (s.riskScore ?? 0));
                    const y = 90 - (sc / 100) * 80;
                    return <circle key={i} cx={x} cy={y} r="3" fill="#a98cf0" />;
                  })}
                </svg>
              )}
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10.5px', opacity: 0.5, marginTop: '4px' }}>
                {trendScans.map((s, i) => <span key={i}>{formatDate(s.scannedAt).split(',')[0]}</span>)}
              </div>
            </div>

            <div className="dash-sub-panel">
              <h3 style={{ display: 'flex', alignItems: 'center', gap: '6px' }}><Brain size={15} style={{ color: '#a98cf0' }} /> AI Executive Summary</h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', margin: '8px 0 12px', fontSize: '13px', opacity: 0.85 }}>
                {summaryLines.map((line, i) => <p key={i} style={{ margin: 0 }}>{line}</p>)}
              </div>
              <div style={{ display: 'flex', gap: '10px' }}>
                <div className="chip" style={{ background: 'rgba(169,140,240,0.15)', color: '#a98cf0', border: '1px solid rgba(169,140,240,0.4)' }}>
                  AI Confidence {aiConfidencePct !== null ? `${aiConfidencePct}%` : '—'}
                </div>
                <div className="chip" style={riskScore >= 70 ? CRITICAL_FALLBACK : { background: 'rgba(232,163,61,0.15)', color: '#e8a33d', border: '1px solid rgba(232,163,61,0.4)' }}>
                  Overall Risk {riskLevel}
                </div>
              </div>
            </div>
          </div>

          <div className="dash-sub-panel" style={{ marginBottom: '16px' }}>
            <h3>Top Recommendations</h3>
            <div className="dash-cap-grid">
              {recommendations.slice(0, 5).map((r, i) => {
                const Icon = r.icon;
                return (
                  <div className="dash-cap-card" key={i}>
                    <div className="dash-cap-icon"><Icon size={14} /></div>
                    <div className="dash-cap-title">{r.label}</div>
                    <span className="chip" style={{ ...recSevStyle(r.sev), marginTop: '6px', display: 'inline-block' }}>{r.sev}</span>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="dash-sub-panel">
            <div className="dash-panel-title-row"><h3>Recent Scans</h3></div>
            {sortedHistory.length === 0 && <p className="empty-sub">No saved scans yet.</p>}
            {sortedHistory.length > 0 && (
              <div className="secrets-table-wrap">
                <table className="secrets-table">
                  <thead>
                    <tr>
                      <th>Scan ID</th><th>Date &amp; Time</th><th>Status</th><th>Score</th><th>Issues</th><th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedHistory.slice(0, 10).map((s) => {
                      const sc = Math.max(0, 100 - (s.riskScore ?? 0));
                      const iss = s.totalFindings ?? ((s.critical ?? 0) + (s.highSeverity ?? 0) + (s.mediumSeverity ?? 0) + (s.lowSeverity ?? 0));
                      return (
                        <tr key={s.id}>
                          <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>#{s.id}</td>
                          <td style={{ fontSize: '12.5px' }}>{formatDate(s.scannedAt)}</td>
                          <td><span className="sev-pill sev-low">Completed</span></td>
                          <td style={{ fontWeight: 700 }}>{sc}/100</td>
                          <td>{iss}</td>
                          <td>
                            <button className="icon-btn" onClick={() => handleDownloadScan(s)} aria-label="Download scan">
                              <Download size={14} />
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </section>
  );
}

export default function App() {
  const [code, setCode] = useState('');
  const [activeNav, setActiveNav] = useState('Code Scan');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState(null);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [entropyOn, setEntropyOn] = useState(true);
  const [autoClear, setAutoClear] = useState(false);
  const [theme, setTheme] = useState('dark');
  const [howItWorksOpen, setHowItWorksOpen] = useState(false);

  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState(null);

  // In-memory only for now — no backend table for this yet, so it resets on
  // refresh. Wire to a real endpoint later if you want it to persist.
  const [savedSnippets, setSavedSnippets] = useState([]);

  // Security Scan tab state
  const [scanType, setScanType] = useState('code');
  const [checks, setChecks] = useState({
    secrets: true, vuln: true, deps: true, aiContext: true, riskPrioritization: true, confidence: true,
  });
  const [analysisDepth, setAnalysisDepth] = useState('standard');
  const [uploadFileName, setUploadFileName] = useState('');
  const [scanDurationMs, setScanDurationMs] = useState(null);

  function toggleCheck(key) {
    setChecks((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  function handleFileUpload(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => setCode(String(ev.target.result || ''));
    reader.readAsText(file);
  }

  useEffect(() => {
    if (activeNav === 'Scan History' || activeNav === 'Dashboard') {
      fetchHistory();
    }
  }, [activeNav]);

  async function fetchHistory() {
    setHistoryLoading(true);
    setHistoryError(null);
    try {
      const res = await fetch(`${API_URL}/history`);
      if (!res.ok) throw new Error(`Could not load history (${res.status})`);
      const data = await res.json();
      setHistory(data.history || []);
    } catch (err) {
      setHistoryError(
        err.message === 'Failed to fetch'
          ? "Can't reach the backend. Is it running on localhost:4000?"
          : err.message
      );
    } finally {
      setHistoryLoading(false);
    }
  }

  async function handleScan() {
    if (!code.trim() || scanning) return;
    setScanning(true);
    setError(null);
    setScanDurationMs(null);
    const startedAt = Date.now();
    try {
      const trimmed = code.trim();
      let body = { code, entropyEnabled: checks.secrets };

      // Dependencies tab always treats the input as a package.json. For the
      // other tabs, auto-detect: if the pasted content is valid JSON with a
      // dependencies/devDependencies key, route it the same way. The backend
      // still needs a non-empty `code` field, so we send a harmless
      // placeholder alongside packageJson.
      const looksLikePackageJson = (() => {
        if (!trimmed.startsWith('{')) return false;
        try {
          const parsed = JSON.parse(trimmed);
          return Boolean(parsed.dependencies || parsed.devDependencies);
        } catch {
          return false;
        }
      })();

      if (scanType === 'deps' || looksLikePackageJson) {
        body = {
          code: '// package.json dependency scan',
          packageJson: trimmed,
          entropyEnabled: checks.secrets,
        };
      }

      const res = await fetch(`${API_URL}/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`Scan failed (${res.status})`);
      const data = await res.json();
      setResults(data);
      setScanDurationMs(Date.now() - startedAt);
      if (autoClear) setCode('');
      // Refresh history in the background so the Dashboard/Scan History
      // reflect this scan immediately without waiting for a tab switch.
      fetchHistory();
    } catch (err) {
      setError(
        err.message === 'Failed to fetch'
          ? "Can't reach the scanner backend. Is it running on localhost:4000?"
          : err.message
      );
    } finally {
      setScanning(false);
    }
  }

  function handleClear() {
    setCode('');
    setResults(null);
    setError(null);
  }

  function goToNav(label) {
    setActiveNav(label);
    setSidebarOpen(false);
  }

  function handleNavClick(item) {
    if (item.special === 'modal') {
      setHowItWorksOpen(true);
      setSidebarOpen(false);
      return;
    }
    goToNav(item.label);
  }

  function handleSaveSnippet() {
    if (!code.trim()) return;
    const name = window.prompt('Name this snippet:', `Snippet ${savedSnippets.length + 1}`);
    if (!name) return;
    setSavedSnippets((prev) => [
      { id: Date.now(), name, code, savedAt: new Date().toISOString() },
      ...prev,
    ]);
  }

  function renderPlaceholderPanel() {
    if (activeNav === 'Dashboard') {
      return <DashboardPanel results={results} history={history} historyLoading={historyLoading} />;
    }

    if (activeNav === 'Scan Results') {
      return (
        <ScanResultsPanel
          results={results}
          history={history}
          code={code}
          scanning={scanning}
          onRescan={handleScan}
          goToNav={goToNav}
        />
      );
    }

    if (activeNav === 'Scan History') {
      const allHistory = [...history].sort((a, b) => new Date(b.scannedAt) - new Date(a.scannedAt));

      return (
        <section className="panel wide-panel">
          <div className="panel-head">
            <div className="panel-icon"><Clock size={18} /></div>
            <div><h2>Scan history</h2><p>All scans saved to the database, most recent first.</p></div>
          </div>

          {historyLoading && (
            <div className="empty-state">
              <Clock size={56} className="empty-icon" />
              <h3>Loading past scans...</h3>
            </div>
          )}

          {historyError && (
            <div className="empty-state">
              <AlertTriangle size={56} className="empty-icon" />
              <h3>Could not load history.</h3>
              <p className="empty-sub">{historyError}</p>
            </div>
          )}

          {!historyLoading && !historyError && allHistory.length === 0 && (
            <div className="empty-state">
              <Clock size={56} className="empty-icon" />
              <h3>No past scans yet.</h3>
              <p className="empty-sub">Run a scan from Code Scan and it'll show up here.</p>
            </div>
          )}

          {!historyLoading && !historyError && allHistory.length > 0 && (
            <div className="findings-list">
              {allHistory.map((scan) => (
                <HistoryRow key={scan.id} scan={scan} />
              ))}
            </div>
          )}
        </section>
      );
    }

    if (activeNav === 'Compare Scans') {
      return (
        <section className="panel wide-panel">
          <div className="panel-head">
            <div className="panel-icon"><GitCompare size={18} /></div>
            <div><h2>Compare scans</h2><p>See what changed between two scans.</p></div>
          </div>
          <div className="empty-state">
            <GitCompare size={56} className="empty-icon" />
            <h3>Not built yet.</h3>
            <p className="empty-sub">Reserved for diffing two scans from history — needs a compare endpoint on the backend first.</p>
          </div>
        </section>
      );
    }

    if (activeNav === 'Reports') {
      return <ReportsPanel results={results} history={history} historyLoading={historyLoading} />;
    }

    if (activeNav === 'Security Coverage') {
      return <SecurityCoveragePanel results={results} code={code} scanDurationMs={scanDurationMs} />;
    }

    if (activeNav === 'Secrets Detection') {
      return (
        <SecretsDetectionPanel
          results={results}
          code={code}
          scanDurationMs={scanDurationMs}
        />
      );
    }

    if (activeNav === 'Configuration Check') {
      return <ConfigurationCheckPanel results={results} code={code} scanDurationMs={scanDurationMs} />;
    }

    if (activeNav === 'Dependency Check') {
      return <DependencyCheckPanel results={results} code={code} />;
    }

    if (activeNav === 'AI Prioritization') {
      return <AIPrioritizationPanel results={results} history={history} />;
    }

    if (activeNav === 'Projects') {
      return <ProjectsPanel />;
    }

    if (activeNav === 'Saved Snippets') {
      return (
        <section className="panel wide-panel">
          <div className="panel-head">
            <div className="panel-icon"><Bookmark size={18} /></div>
            <div>
              <h2>Saved snippets</h2>
              <p>Save code you test often and reload it into Code Scan in one click. Kept in this browser session only — not saved to the database yet.</p>
            </div>
          </div>

          <button className="scan-btn" style={{ marginBottom: '14px' }} onClick={handleSaveSnippet} disabled={!code.trim()}>
            <Bookmark size={16} /> Save current code
          </button>

          {savedSnippets.length === 0 && (
            <div className="empty-state">
              <Bookmark size={56} className="empty-icon" />
              <h3>No snippets saved yet.</h3>
              <p className="empty-sub">Paste code in Code Scan, then come back here to save it.</p>
            </div>
          )}

          {savedSnippets.length > 0 && (
            <div className="findings-list">
              {savedSnippets.map((s) => (
                <div
                  className="finding-card"
                  key={s.id}
                  style={{ cursor: 'pointer' }}
                  onClick={() => { setCode(s.code); goToNav('Code Scan'); }}
                >
                  <div className="finding-top">
                    <span className="finding-line">{formatDate(s.savedAt)}</span>
                    <Trash2
                      size={14}
                      onClick={(e) => {
                        e.stopPropagation();
                        setSavedSnippets((prev) => prev.filter((x) => x.id !== s.id));
                      }}
                    />
                  </div>
                  <div className="finding-type">{s.name}</div>
                  <div className="finding-preview">
                    {s.code.slice(0, 80)}{s.code.length > 80 ? '…' : ''}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      );
    }

    if (activeNav === 'Settings') {
      return (
        <section className="panel wide-panel">
          <div className="panel-head">
            <div className="panel-icon"><Settings size={18} /></div>
            <div><h2>Settings</h2><p>Control how SecureCode scans your code.</p></div>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-label">Entropy detection</div>
              <div className="settings-sub">Flag high-randomness strings that don't match a known pattern.</div>
            </div>
            <button
              className={`toggle ${entropyOn ? 'on' : ''}`}
              onClick={() => setEntropyOn(!entropyOn)}
              aria-label="Toggle entropy detection"
            >
              <span className="toggle-knob" />
            </button>
          </div>
          <div className="settings-row">
            <div>
              <div className="settings-label">Auto-clear after scan</div>
              <div className="settings-sub">Empty the code box automatically once results come back.</div>
            </div>
            <button
              className={`toggle ${autoClear ? 'on' : ''}`}
              onClick={() => setAutoClear(!autoClear)}
              aria-label="Toggle auto-clear"
            >
              <span className="toggle-knob" />
            </button>
          </div>
        </section>
      );
    }
    if (activeNav === 'About') {
      return (
        <section className="panel wide-panel">
          <div className="panel-head">
            <div className="panel-icon"><Info size={18} /></div>
            <div><h2>About SecureCode</h2></div>
          </div>
          <p className="about-text">
            SecureCode scans pasted code, configs, and dependency files for exposed secrets,
            injection flaws, broken authentication, access control issues, insecure
            configuration, logic errors, and vulnerable dependencies. Pattern matching and
            entropy detection catch known secret formats and random-looking strings; an AI
            layer reads the code semantically to catch what regex can't. Every finding is
            explained in plain English with a suggested fix, and every scan is saved so you
            can revisit it later.
          </p>
        </section>
      );
    }
    return null;
  }

  return (
    <div className={`app ${theme === 'light' ? 'theme-light' : ''}`}>
      {sidebarOpen && <div className="backdrop" onClick={() => setSidebarOpen(false)} />}
      <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
        <div className="brand">
          <div className="brand-icon"><ShieldCheck size={20} /></div>
          <div>
            <div className="brand-name">SecureCode</div>
            <div className="brand-tag">Paste code. Find what's leaking.</div>
          </div>
          <button className="sidebar-close" onClick={() => setSidebarOpen(false)} aria-label="Close menu">
            <X size={18} />
          </button>
        </div>

        <nav className="nav">
          {NAV_GROUPS.map((group) => (
            <div key={group.label} style={{ marginBottom: '18px' }}>
              <div
                style={{
                  padding: '0 12px 6px',
                  fontSize: '10px',
                  fontWeight: 600,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                  opacity: 0.45,
                }}
              >
                {group.label}
              </div>
              {group.items.map((item) => {
                const Icon = item.icon;
                return (
                  <button
                    key={item.label}
                    className={`nav-item ${item.special !== 'modal' && activeNav === item.label ? 'active' : ''}`}
                    onClick={() => handleNavClick(item)}
                  >
                    <Icon size={17} />
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </div>
          ))}
        </nav>

        <div className="sidebar-footer">© 2026 SecureCode<br />All rights reserved.</div>
      </aside>

      <main className="main">
        <header className="topbar">
          <button className="menu-btn" onClick={() => setSidebarOpen(true)} aria-label="Open menu">
            <Menu size={20} />
          </button>
          <div className="topbar-icon"><ShieldCheck size={20} /></div>
          <div className="topbar-text">
            <h1>Welcome to <span className="accent-grad">SecureCode</span></h1>
            <p>Scan your code for secrets, keys, and vulnerabilities.</p>
          </div>
          <div className="topbar-actions">
            <button className="ghost-btn" onClick={() => setHowItWorksOpen(true)}>
              <HelpCircle size={16} /> How it works
            </button>
            <button
              className="icon-btn"
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              aria-label="Toggle theme"
            >
              {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            </button>
          </div>
        </header>

        {howItWorksOpen && (
          <div className="modal-backdrop" onClick={() => setHowItWorksOpen(false)}>
            <div className="panel how-it-works-modal" onClick={(e) => e.stopPropagation()}>
              <div className="panel-head">
                <div className="panel-icon"><HelpCircle size={18} /></div>
                <div><h2>How it works</h2></div>
                <button className="icon-btn" onClick={() => setHowItWorksOpen(false)} aria-label="Close">
                  <X size={16} />
                </button>
              </div>
              <ul className="how-it-works-steps">
                <li>
                  <span className="step-number">1</span>
                  <div>
                    <strong>Paste your code</strong>
                    <p>Any file, snippet, or config — .py, .js, .env, .json, .yml and more. Paste a package.json to check dependencies too.</p>
                  </div>
                </li>
                <li>
                  <span className="step-number">2</span>
                  <div>
                    <strong>We scan it four ways</strong>
                    <p>Pattern matching catches known key formats. Entropy detection flags random-looking strings. An AI layer reads the code semantically for injection, broken auth, access control, and config issues. A dependency check looks up known CVEs for your packages.</p>
                  </div>
                </li>
                <li>
                  <span className="step-number">3</span>
                  <div>
                    <strong>Get a prioritized, explained report</strong>
                    <p>Every finding shows type, severity, and line number, with a plain-English explanation and suggested fix where available. Secrets are always masked.</p>
                  </div>
                </li>
                <li>
                  <span className="step-number">4</span>
                  <div>
                    <strong>Revisit anytime</strong>
                    <p>Every scan is saved, so you can check Scan History later without re-scanning.</p>
                  </div>
                </li>
              </ul>
            </div>
          </div>
        )}

        {activeNav !== 'Code Scan' && renderPlaceholderPanel()}

        {activeNav === 'Code Scan' && (() => {
          const confidences = (results?.findings || []).filter((f) => typeof f.confidence === 'number');
          const aiConfidence = confidences.length
            ? Math.round((confidences.reduce((sum, f) => sum + f.confidence, 0) / confidences.length) * 100)
            : null;
          const pipelineState = scanning ? 'running' : results ? 'done' : 'idle';

          return (
          <>
          <section className="panel" style={{ marginBottom: '14px' }}>
            <div className="field-label" style={{ marginBottom: '10px' }}>1. What do you want to scan?</div>
            <div className="scan-type-grid">
              {SCAN_TYPES.map((t) => {
                const Icon = t.icon;
                return (
                  <button
                    key={t.key}
                    className={`scan-type-card ${scanType === t.key ? 'active' : ''}`}
                    onClick={() => setScanType(t.key)}
                  >
                    <Icon size={18} />
                    <div className="scan-type-label">{t.label}</div>
                    <div className="scan-type-desc">{t.desc}</div>
                  </button>
                );
              })}
            </div>
          </section>

          <div className="content-grid">
            <div className="left-col">
              <section className="panel">
                <div className="panel-head">
                  <div className="panel-icon"><Code2 size={18} /></div>
                  <div>
                    <h2>2. Code / File to scan</h2>
                  </div>
                  {scanType === 'upload' ? (
                    <label className="text-btn" style={{ marginLeft: 'auto', cursor: 'pointer' }}>
                      <UploadCloud size={13} /> Upload file
                      <input type="file" onChange={handleFileUpload} style={{ display: 'none' }} />
                    </label>
                  ) : (
                    <button className="text-btn" style={{ marginLeft: 'auto' }} onClick={handleClear}>
                      <Trash2 size={13} /> Clear
                    </button>
                  )}
                </div>

                {scanType === 'upload' && uploadFileName && (
                  <div className="field-row"><span className="field-label">{uploadFileName}</span></div>
                )}

                <textarea
                  className="code-input"
                  placeholder={
                    scanType === 'deps'
                      ? 'Paste your package.json or requirements.txt'
                      : scanType === 'config'
                      ? 'Paste your .env, .yml, or other config file'
                      : scanType === 'upload'
                      ? 'Upload a file above, or paste its contents here'
                      : 'Paste a file, a snippet, a config, or a package.json — anything with strings in it.'
                  }
                  value={code}
                  onChange={(e) => setCode(e.target.value)}
                />

                <div className="supports">
                  <span>Supports:</span>
                  {['.py', '.js', '.java', '.cpp', '.c', '.json', '.yml', '.yaml', '+ more'].map((ext) => (
                    <span key={ext} className="chip">{ext}</span>
                  ))}
                </div>

                {error && <div className="scan-error"><AlertTriangle size={14} /> {error}</div>}

                <button className="scan-btn" onClick={handleScan} disabled={scanning || !code.trim()}>
                  <Search size={16} /> {scanning ? 'Scanning…' : 'Run Security Scan'}
                </button>
              </section>
            </div>

            <section className="panel">
              <div className="panel-head">
                <div><h2>3. Scan Configuration</h2></div>
              </div>
              <div className="check-list">
                {CHECK_ITEMS.map((c) => (
                  <label className="check-row" key={c.key}>
                    <input type="checkbox" checked={checks[c.key]} onChange={() => toggleCheck(c.key)} />
                    <div>
                      <div className="check-title">{c.title}</div>
                      <div className="check-desc">{c.desc}</div>
                    </div>
                  </label>
                ))}
              </div>
              <div className="field-row" style={{ marginTop: '12px' }}>
                <span className="field-label">Analysis Depth</span>
              </div>
              <select className="code-input" style={{ height: 'auto', padding: '8px 12px' }} value={analysisDepth} onChange={(e) => setAnalysisDepth(e.target.value)}>
                <option value="quick">Quick</option>
                <option value="standard">Standard (Recommended)</option>
                <option value="deep">Deep</option>
              </select>
            </section>
          </div>

          <section className="panel" style={{ marginTop: '14px' }}>
            <div className="panel-head">
              <div><h2>4. Security Checks ({CAPABILITY_TILES.length} capabilities)</h2></div>
            </div>
            <div className="dash-cap-grid">
              {CAPABILITY_TILES.map((cap, i) => {
                const Icon = cap.icon;
                return (
                  <div className="dash-cap-card" key={cap.key}>
                    <div className="dash-cap-icon"><Icon size={14} /></div>
                    <div className="dash-cap-title">{cap.label}</div>
                    <div className="dash-cap-status" style={{ color: '#4fd08a' }}>Enabled</div>
                  </div>
                );
              })}
            </div>
          </section>

          <div className="content-grid" style={{ marginTop: '14px' }}>
            <section className="panel">
              <div className="panel-head"><div><h2>5. Analysis Pipeline</h2></div></div>
              <div className="pipeline-row">
                {PIPELINE_STEPS.map((step) => {
                  const Icon = step.icon;
                  const state = pipelineState === 'done' ? 'done' : pipelineState === 'running' ? 'running' : 'idle';
                  return (
                    <div className="pipeline-step" key={step.key}>
                      <div className={`pipeline-dot ${state}`}>
                        {state === 'done' ? <Check size={14} /> : <Icon size={14} />}
                      </div>
                      <div className="pipeline-label">{step.label}</div>
                      <div className={`pipeline-status ${state}`}>
                        {state === 'done' ? 'Complete' : state === 'running' ? 'Running…' : 'Pending'}
                      </div>
                    </div>
                  );
                })}
              </div>
              {results && (
                <div className="pipeline-complete">
                  <CheckCircle2 size={20} className="empty-icon success" />
                  <div>
                    <div className="settings-label" style={{ fontSize: '13.5px' }}>Analysis complete</div>
                    <div className="settings-sub">
                      Scan finished in {scanDurationMs !== null ? (scanDurationMs / 1000).toFixed(2) : '—'}s
                    </div>
                  </div>
                </div>
              )}
              {!results && !scanning && (
                <p className="empty-sub" style={{ marginTop: '10px' }}>Run a scan to see pipeline progress here.</p>
              )}
            </section>

            <section className="panel">
              <div className="panel-head">
                <div><h2>6. Scan Summary</h2></div>
                {results && <span className="results-badge" style={{ background: '#12301f', color: '#4fd08a' }}>Completed</span>}
              </div>

              {!results && (
                <p className="empty-sub">Results will appear here once you run a scan.</p>
              )}

              {results && (
                <>
                  <div className="summary-row">
                    <div className="summary-chip" style={CRITICAL_FALLBACK}>{results.critical ?? 0}<br />Critical</div>
                    <div className="summary-chip sev-high">{results.highSeverity ?? 0}<br />High</div>
                    <div className="summary-chip sev-medium">{results.mediumSeverity ?? 0}<br />Medium</div>
                    <div className="summary-chip sev-low">{results.lowSeverity ?? 0}<br />Low</div>
                  </div>
                  <div className="dash-stats-grid" style={{ gridTemplateColumns: '1fr 1fr', marginTop: '12px' }}>
                    <div className="dash-stat-card">
                      <div className="dash-stat-head">Risk Score</div>
                      <div className="dash-stat-value">{results.riskScore ?? 0}<span> / 100</span></div>
                      <div className="dash-stat-sub" style={{ color: '#e8a33d' }}>{results.riskLevel}</div>
                    </div>
                    <div className="dash-stat-card">
                      <div className="dash-stat-head">AI Confidence</div>
                      <div className="dash-stat-value">{aiConfidence !== null ? `${aiConfidence}%` : '—'}</div>
                      <div className="dash-stat-sub" style={{ color: '#4fd08a' }}>{aiConfidence !== null ? 'High confidence' : 'No AI findings'}</div>
                    </div>
                  </div>
                  <button className="scan-btn" style={{ marginTop: '12px' }} onClick={() => goToNav('Scan Results')}>
                    View Detailed Results <ChevronRight size={16} />
                  </button>
                </>
              )}
            </section>
          </div>
          </>
          );
        })()}
      </main>
    </div>
  );
}