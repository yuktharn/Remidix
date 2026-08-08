require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { scanCode } = require("./detectors");
const { analyzeWithLLM } = require("./llmAnalyzer");
const { scanDependencies } = require("./depScanner");
const { buildRiskReport } = require("./riskEngine");
const pool = require("./db");
const { encryptToken, decryptToken } = require("./tokenCrypto");
const { fetchRepoFiles } = require("./githubFetcher");

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 4000;

// Converts a `projects` DB row (+ its PR rows) into the camelCase shape
// ProjectsPanel.jsx expects. Token columns are intentionally never
// included here — the encrypted token never leaves the backend.
function formatProject(row, prRows = []) {
  return {
    id: row.id,
    name: row.name,
    platform: row.platform,
    repos: typeof row.repos_json === "string" ? JSON.parse(row.repos_json) : row.repos_json,
    securityScore: row.security_score,
    riskLevel: row.risk_level,
    totalIssues: row.total_issues,
    critical: row.critical_count,
    high: row.high_count,
    medium: row.medium_count,
    low: row.low_count,
    lastScan: row.last_scan,
    autoScanEnabled: Boolean(row.auto_scan_enabled),
    autoScanFrequency: row.auto_scan_frequency,
    createdAt: row.created_at,
    remediationProgress: row.remediation_progress,
    prs: prRows.map((pr) => ({
      id: pr.id,
      title: pr.title,
      status: pr.status,
      createdAt: pr.created_at,
    })),
  };
}

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/scan", async (req, res) => {
  const { code, files, entropyEnabled = true, packageJson } = req.body;

  if (!code && !files) {
    return res.status(400).json({ error: "Provide either 'code' (string) or 'files' (array of {name, content})" });
  }

  try {
    // ---- 1. Pattern + entropy scan (existing, synchronous, instant) ----
    let patternFindings;
    let combinedCode; // sent to the LLM for semantic analysis
    let packageJsonContent = packageJson || null;

    if (code) {
      const result = scanCode(code, { entropyEnabled });
      patternFindings = result.findings;
      combinedCode = code;
    } else {
      const pkgFile = files.find((f) => f.name.endsWith("package.json"));
      if (pkgFile) packageJsonContent = pkgFile.content;

      const perFileResults = files.map((f) => ({ fileName: f.name, ...scanCode(f.content, { entropyEnabled }) }));
      patternFindings = perFileResults.flatMap((r) => r.findings.map((f) => ({ ...f, fileName: r.fileName })));

      // cap combined code sent to the LLM so requests stay fast and cheap
      combinedCode = files.map((f) => `// ${f.name}\n${f.content}`).join("\n\n").slice(0, 12000);
    }

    // ---- 2. Semantic (LLM) + dependency scans run in parallel ----
    const [llmFindings, depFindings] = await Promise.all([
      analyzeWithLLM(combinedCode),
      packageJsonContent ? scanDependencies(packageJsonContent) : Promise.resolve([]),
    ]);

    // ---- 3. Merge everything into one prioritized risk report ----
    const report = buildRiskReport({ patternFindings, llmFindings, depFindings });

    // ---- 4. Save to DB (best-effort — a save failure shouldn't break the response) ----
    try {
      await pool.query(
        `INSERT INTO scan_history
         (total_findings, high_severity, medium_severity, low_severity, findings_json, risk_score, risk_level)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          report.totalFindings,
          report.highSeverity,
          report.mediumSeverity,
          report.lowSeverity,
          JSON.stringify(report.findings),
          report.riskScore,
          report.riskLevel,
        ]
      );
    } catch (dbErr) {
      console.error("Failed to save scan to database:", dbErr.message);
    }

    return res.json({ source: code ? "single-input" : "multi-file", ...report });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Scan failed", details: err.message });
  }
});

app.get("/history", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, scanned_at, total_findings, high_severity, medium_severity, low_severity, findings_json, risk_score, risk_level
       FROM scan_history
       ORDER BY scanned_at DESC
       LIMIT 50`
    );

    const history = rows.map((row) => ({
      id: row.id,
      scannedAt: row.scanned_at,
      totalFindings: row.total_findings,
      highSeverity: row.high_severity,
      mediumSeverity: row.medium_severity,
      lowSeverity: row.low_severity,
      riskScore: row.risk_score,
      riskLevel: row.risk_level,
      findings: row.findings_json,
    }));

    return res.json({ history });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Could not fetch history", details: err.message });
  }
});

// ---------------------------------------------------------------------
// Projects
// ---------------------------------------------------------------------

app.get("/projects", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT * FROM projects ORDER BY created_at DESC`
    );

    const projects = await Promise.all(
      rows.map(async (row) => {
        const [prRows] = await pool.query(
          `SELECT id, title, status, created_at, merged_at
           FROM project_prs WHERE project_id = ? ORDER BY created_at DESC`,
          [row.id]
        );
        return formatProject(row, prRows);
      })
    );

    return res.json({ projects });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Could not fetch projects", details: err.message });
  }
});

app.post("/projects", async (req, res) => {
  const { name, platform, repos, settings = {}, token } = req.body;

  if (!name || !platform || !Array.isArray(repos) || repos.length === 0) {
    return res.status(400).json({ error: "Provide 'name', 'platform', and a non-empty 'repos' array" });
  }
  if (!["GitHub", "GitLab"].includes(platform)) {
    return res.status(400).json({ error: "'platform' must be 'GitHub' or 'GitLab'" });
  }

  try {
    let encryptedToken = null, tokenIv = null, tokenAuthTag = null;
    if (token) {
      const enc = encryptToken(token);
      encryptedToken = enc.encryptedToken;
      tokenIv = enc.iv;
      tokenAuthTag = enc.authTag;
    }

    const [result] = await pool.query(
      `INSERT INTO projects
       (name, platform, repos_json, auto_scan_enabled, auto_scan_frequency, encrypted_token, token_iv, token_auth_tag)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        name,
        platform,
        JSON.stringify(repos),
        settings.autoScan !== undefined ? Boolean(settings.autoScan) : true,
        settings.scanFrequency || "daily",
        encryptedToken,
        tokenIv,
        tokenAuthTag,
      ]
    );

    const [rows] = await pool.query(`SELECT * FROM projects WHERE id = ?`, [result.insertId]);
    return res.status(201).json(formatProject(rows[0], []));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Could not create project", details: err.message });
  }
});

app.get("/projects/:projectId", async (req, res) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM projects WHERE id = ?`, [req.params.projectId]);
    if (rows.length === 0) return res.status(404).json({ error: "Project not found" });

    const [prRows] = await pool.query(
      `SELECT id, title, status, created_at, merged_at
       FROM project_prs WHERE project_id = ? ORDER BY created_at DESC`,
      [req.params.projectId]
    );

    return res.json(formatProject(rows[0], prRows));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Could not fetch project", details: err.message });
  }
});

app.patch("/projects/:projectId", async (req, res) => {
  const { autoScanEnabled, autoScanFrequency } = req.body;

  if (autoScanEnabled === undefined && autoScanFrequency === undefined) {
    return res.status(400).json({ error: "Provide 'autoScanEnabled' and/or 'autoScanFrequency' to update" });
  }
  if (autoScanFrequency && !["on-push", "daily", "weekly"].includes(autoScanFrequency)) {
    return res.status(400).json({ error: "'autoScanFrequency' must be one of: on-push, daily, weekly" });
  }

  try {
    const fields = [];
    const values = [];
    if (autoScanEnabled !== undefined) { fields.push("auto_scan_enabled = ?"); values.push(Boolean(autoScanEnabled)); }
    if (autoScanFrequency !== undefined) { fields.push("auto_scan_frequency = ?"); values.push(autoScanFrequency); }
    values.push(req.params.projectId);

    const [result] = await pool.query(`UPDATE projects SET ${fields.join(", ")} WHERE id = ?`, values);
    if (result.affectedRows === 0) return res.status(404).json({ error: "Project not found" });

    const [rows] = await pool.query(`SELECT * FROM projects WHERE id = ?`, [req.params.projectId]);
    const [prRows] = await pool.query(
      `SELECT id, title, status, created_at, merged_at
       FROM project_prs WHERE project_id = ? ORDER BY created_at DESC`,
      [req.params.projectId]
    );
    return res.json(formatProject(rows[0], prRows));
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Could not update project", details: err.message });
  }
});

// ---------------------------------------------------------------------
// Trigger a scan: fetches the repo's files via the GitHub API, runs them
// through the existing scanCode/analyzeWithLLM/scanDependencies pipeline,
// and persists the results. Responds immediately (202) and does the actual
// work in the background since fetching + LLM analysis can take a while;
// the frontend is expected to poll GET /projects/:id/scans for completion.
// ---------------------------------------------------------------------
app.post("/projects/:projectId/scan", async (req, res) => {
  const projectId = req.params.projectId;
  try {
    const [projRows] = await pool.query(`SELECT * FROM projects WHERE id = ?`, [projectId]);
    if (projRows.length === 0) return res.status(404).json({ error: "Project not found" });
    const project = projRows[0];

    const [scanResult] = await pool.query(
      `INSERT INTO project_scans (project_id, status) VALUES (?, 'in_progress')`,
      [projectId]
    );
    const scanId = scanResult.insertId;

    res.status(202).json({
      scanId,
      projectId: Number(projectId),
      status: "started",
      startedAt: new Date().toISOString(),
    });

    // ---- background work (runs after the response above is already sent) ----
    (async () => {
      try {
        if (!project.encrypted_token) {
          throw new Error("No stored access token for this project");
        }
        const token = decryptToken(project.encrypted_token, project.token_iv, project.token_auth_tag);
        const repos = typeof project.repos_json === "string" ? JSON.parse(project.repos_json) : project.repos_json;
        const { url, branch } = repos[0];

        const files = await fetchRepoFiles(url, branch || "main", token);
        if (files.length === 0) throw new Error("No scannable source files found in repo");

        const pkgFile = files.find((f) => f.name.endsWith("package.json"));
        const perFileResults = files.map((f) => ({ fileName: f.name, ...scanCode(f.content, { entropyEnabled: true }) }));
        const patternFindings = perFileResults.flatMap((r) => r.findings.map((f) => ({ ...f, fileName: r.fileName })));
        const combinedCode = files.map((f) => `// ${f.name}\n${f.content}`).join("\n\n").slice(0, 12000);

        const [llmFindings, depFindings] = await Promise.all([
          analyzeWithLLM(combinedCode),
          pkgFile ? scanDependencies(pkgFile.content) : Promise.resolve([]),
        ]);

        const report = buildRiskReport({ patternFindings, llmFindings, depFindings });

        // Count by severity — robust to however buildRiskReport labels findings.
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const f of report.findings || []) {
          const sev = (f.severity || "low").toLowerCase();
          if (counts[sev] !== undefined) counts[sev] += 1;
        }
        const totalIssues = counts.critical + counts.high + counts.medium + counts.low;
        // riskScore is "how bad" (higher = worse); securityScore is the inverse shown on the dashboard.
        const securityScore = Math.max(0, Math.min(100, Math.round(100 - (report.riskScore ?? 0))));

        await pool.query(
          `UPDATE project_scans SET status='completed', risk_score=?, risk_level=?, findings_json=?,
           critical_count=?, high_count=?, medium_count=?, low_count=?, total_findings=?
           WHERE id=?`,
          [report.riskScore, report.riskLevel, JSON.stringify(report.findings), counts.critical, counts.high, counts.medium, counts.low, totalIssues, scanId]
        );

        await pool.query(
          `UPDATE projects SET security_score=?, risk_level=?, total_issues=?,
           critical_count=?, high_count=?, medium_count=?, low_count=?, last_scan=NOW()
           WHERE id=?`,
          [securityScore, report.riskLevel, totalIssues, counts.critical, counts.high, counts.medium, counts.low, projectId]
        );
      } catch (bgErr) {
        console.error(`Scan ${scanId} failed:`, bgErr.message);
        await pool.query(`UPDATE project_scans SET status='failed' WHERE id=?`, [scanId]).catch(() => {});
      }
    })();
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Could not start scan", details: err.message });
  }
});

app.get("/projects/:projectId/scans", async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, scanned_at, status, risk_score, risk_level, findings_json,
              critical_count, high_count, medium_count, low_count, total_findings
       FROM project_scans
       WHERE project_id = ?
       ORDER BY scanned_at DESC
       LIMIT 50`,
      [req.params.projectId]
    );

    const scans = rows.map((row) => ({
      id: row.id,
      projectId: Number(req.params.projectId),
      scannedAt: row.scanned_at,
      status: row.status,
      riskScore: row.risk_score,
      riskLevel: row.risk_level,
      findings: row.findings_json,
      critical: row.critical_count,
      high: row.high_count,
      medium: row.medium_count,
      low: row.low_count,
    }));

    return res.json({ scans });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Could not fetch project scan history", details: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`SecureCode backend running on http://localhost:${PORT}`);
});