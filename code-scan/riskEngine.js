// riskEngine.js
// ---------------------------------------------------------------------------
// Merges the findings produced by the three real analyzers (static pattern
// detectors, the LLM semantic analyzer and the OSV dependency scanner) into a
// single, de-duplicated report and derives every aggregate number the rest of
// the app relies on: total findings, per-severity counts, a 0-100 security
// score, a 0-100 risk score, a human risk level, a category breakdown and the
// de-duplicated recommendation list.
//
// NOTE: this file previously contained a stray copy of package.json, which
// made `require("./riskEngine").buildRiskReport` undefined and crashed every
// /scan and project scan. It is now a real implementation again.
//
// Nothing here is mocked — every number is computed from the findings that the
// analyzers actually returned for the exact code that was scanned.
// ---------------------------------------------------------------------------

const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];

function normSeverity(sev) {
  const s = String(sev || "").toLowerCase();
  if (s.startsWith("crit")) return "Critical";
  if (s.startsWith("high")) return "High";
  if (s.startsWith("med")) return "Medium";
  if (s.startsWith("low")) return "Low";
  if (s.startsWith("info")) return "Info";
  return "Medium";
}

// A finding is uniquely identified by the file it is in, the line it is on and
// its type. The same weakness can legitimately be reported by both the static
// detectors and the LLM — when that happens we keep the higher-confidence copy
// so the detail view shows the richest explanation/fix, and the counts don't
// double up.
function dedupeKey(f) {
  const file = (f.fileName || "").toLowerCase();
  const line = f.line || 0;
  const type = String(f.type || "").toLowerCase();
  return `${file}|${line}|${type}`;
}

function dedupeFindings(findings) {
  const map = new Map();
  for (const raw of findings) {
    const f = { ...raw, severity: normSeverity(raw.severity) };
    const key = dedupeKey(f);
    const existing = map.get(key);
    if (!existing) {
      map.set(key, f);
      continue;
    }
    // Prefer the copy with the higher confidence; break ties by preferring the
    // one that actually carries a corrected-code snippet (richer detail view).
    const fConf = typeof f.confidence === "number" ? f.confidence : 0;
    const eConf = typeof existing.confidence === "number" ? existing.confidence : 0;
    if (fConf > eConf || (fConf === eConf && f.correctedCode && !existing.correctedCode)) {
      map.set(key, f);
    }
  }
  return [...map.values()];
}

// Security score: start at 100 and subtract a capped penalty per severity tier.
// Tier caps stop a repo with hundreds of "High" issues from pinning every
// project at 0 while still letting Critical issues dominate the score. This is
// deterministic and fully explained by the counts below — no black box.
//   Critical: 17 each, capped at 51   (3 criticals already cost half the score)
//   High:      6 each, capped at 30
//   Medium:    3 each, capped at 15
//   Low:       1 each, capped at 8
// Info findings are informational only and never reduce the score.
function computeSecurityScore({ Critical, High, Medium, Low }) {
  const penalty =
    Math.min(51, Critical * 17) +
    Math.min(30, High * 6) +
    Math.min(15, Medium * 3) +
    Math.min(8, Low * 1);
  return Math.max(0, Math.min(100, 100 - penalty));
}

function riskLevelFromScore(riskScore) {
  if (riskScore >= 70) return "Critical Risk";
  if (riskScore >= 40) return "High Risk";
  if (riskScore >= 15) return "Medium Risk";
  return "Low Risk";
}

// Best-practice guidance is only emitted for categories that actually appear in
// this scan's findings, so it can never describe an issue the repo doesn't have.
const BEST_PRACTICE_BY_CATEGORY = {
  "Secrets Exposure": "Move every credential into environment variables or a secrets manager and rotate anything that was committed.",
  "Injection Flaws": "Use parameterized queries and context-aware output encoding; never build queries or HTML from raw user input.",
  "Insecure Authentication": "Hash passwords with bcrypt/Argon2 and authenticate against stored credentials with role-based access control.",
  "Security Misconfigurations": "Disable debug mode, keep TLS verification on and restrict CORS to an explicit allow-list in production.",
  "Information Disclosure": "Return generic error messages to clients and keep stack traces and secrets out of logs and responses.",
  "Broken Access Control": "Enforce authorization on every request and validate that the caller owns the object being accessed.",
  "Outdated Dependencies": "Upgrade the flagged packages to their fixed versions and enable automated dependency updates.",
  "Cryptographic Failures": "Use modern cryptographic algorithms (AES-256-GCM, SHA-256/SHA-3) and never use MD5/SHA1 for security-sensitive operations.",
  "CSRF": "Implement CSRF token validation on all state-changing endpoints and use SameSite cookie attributes.",
  "Missing / Weak Security Headers": "Enable security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options) using helmet or framework defaults.",
  "Broken Session Management": "Set secure cookie flags (httpOnly, secure, sameSite), configure session expiration, and regenerate session IDs after login.",
  "Improper Error Handling": "Return generic error messages to clients and log detailed errors server-side only.",
  "Sensitive Data Exposure": "Never include sensitive fields (passwords, tokens, PII) in HTTP responses; use DTOs and response serializers.",
  "Software Supply Chain": "Pin dependency versions, audit transitive dependencies, and enable automated vulnerability scanning in CI/CD.",
};

function buildRiskReport({
  patternFindings = [],
  llmFindings = [],
  depFindings = [],
  code = "",
  fullCorrectedCode = null,
} = {}) {
  const findings = dedupeFindings([...patternFindings, ...llmFindings, ...depFindings]);

  // Stable ordering: most severe first, then by file, then by line — so the UI
  // and the "top vulnerabilities" lists are deterministic across scans.
  const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
  findings.sort((a, b) => {
    const s = (order[a.severity] ?? 5) - (order[b.severity] ?? 5);
    if (s !== 0) return s;
    const fa = (a.fileName || "").localeCompare(b.fileName || "");
    if (fa !== 0) return fa;
    return (a.line || 0) - (b.line || 0);
  });

  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const securityScore = computeSecurityScore(counts);
  const riskScore = 100 - securityScore;
  const riskLevel = riskLevelFromScore(riskScore);

  const byCategory = {};
  for (const f of findings) {
    const c = f.category || "Other";
    byCategory[c] = (byCategory[c] || 0) + 1;
  }

  // Recommendations are just the distinct, real "fix" strings the analyzers
  // produced for this code — no invented advice.
  const recommendations = [...new Set(findings.map((f) => f.fix).filter(Boolean))];

  const bestPractices = Object.keys(byCategory)
    .map((c) => BEST_PRACTICE_BY_CATEGORY[c])
    .filter(Boolean);

  return {
    findings,
    totalFindings: findings.length,
    criticalCount: counts.Critical,
    highCount: counts.High,
    mediumCount: counts.Medium,
    lowCount: counts.Low,
    infoCount: counts.Info,
    riskScore,
    securityScore,
    riskLevel,
    byCategory,
    recommendations,
    bestPractices,
    fullCorrectedCode: fullCorrectedCode || null,
  };
}

module.exports = { buildRiskReport, computeSecurityScore, dedupeFindings, normSeverity, SEVERITIES };
