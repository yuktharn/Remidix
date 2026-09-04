// test_repo_details.mjs
// ---------------------------------------------------------------------------
// Offline proof that the repository-details feature is driven entirely by REAL
// scanner output — no DB, no network, no mock data. It wires together:
//
//   * the REAL static detectors      (./detectors.js)
//   * the NEW risk aggregator         (./riskEngine.js)
//   * the SHARED UI logic module      (../frontend/src/vulnLogic.js)
//
// and asserts the exact contracts the UI relies on:
//   1. buildRiskReport is a real function (guards the old package.json-corruption
//      regression that made every scan crash).
//   2. Findings are grouped per file; clicking a file filters to only its issues.
//   3. Multiple vulnerabilities in the SAME file appear independently.
//   4. Every static finding's snippet start line + the single changed line land
//      exactly on finding.line  -> red (vulnerable) / green (fixed) highlight is
//      always on the true line.
//   5. vulnerable/corrected snippets are equal length (clean line-for-line diff).
//   6. The security score is the deterministic function of the real severities.
//   7. Severity filtering returns only findings of that severity.
//   8. The file tree rolls per-file counts up to the correct folder totals.
//
// Run:  node test_repo_details.mjs
// ---------------------------------------------------------------------------

import {
  normSev, sevMeta, codeStartLine, diffLines, findingKey,
  computeTreeAggregates, buildFileTree, sortedChildren, SEV_ORDER,
} from '../frontend/src/vulnLogic.js';

// Dynamically import the two CommonJS backend modules by file URL (works on
// Windows) so this ESM test can consume them.
const detMod  = await import(new URL('./detectors.js', import.meta.url).href);
const riskMod = await import(new URL('./riskEngine.js', import.meta.url).href);

const scanCode       = detMod.scanCode       || detMod.default?.scanCode;
const buildRiskReport = riskMod.buildRiskReport || riskMod.default?.buildRiskReport;

// --- tiny test harness ------------------------------------------------------
let passed = 0;
const failures = [];
function assert(cond, msg) {
  if (cond) { passed++; }
  else { failures.push(msg); console.log('  ✗ ' + msg); }
}
function eq(a, b, msg) { assert(a === b, `${msg} (expected ${JSON.stringify(b)}, got ${JSON.stringify(a)})`); }

// --- 1. regression guard: buildRiskReport must exist ------------------------
eq(typeof scanCode, 'function', 'detectors.scanCode is callable');
eq(typeof buildRiskReport, 'function', 'riskEngine.buildRiskReport is callable (not the corrupted package.json)');

// --- a small, real multi-file "repository" ----------------------------------
// Two secrets in ONE file (independence) + one secret in a nested file + a
// completely clean file (must contribute zero findings).
const FILES = [
  {
    name: 'src/index.js',
    content: [
      'const region = "us-east-1";',                       // 1 clean
      'const awsKey = "AKIAABCDEFGHIJKLMNOP";',            // 2 AWS key (Critical)
      'const svc = init(region);',                         // 3 clean
      'const apiKey = "AbCdEf0123456789XYZlongTOKEN";',    // 4 API key (Critical)
      'module.exports = svc;',                             // 5 clean
    ].join('\n'),
  },
  {
    name: 'src/config/secrets.js',
    content: [
      'const cfg = {};',                                             // 1
      'cfg.stripe = "STRIPE_TEST_KEY_PLACEHOLDER";',        // 2 Stripe (Critical)
      'export default cfg;',                                         // 3
    ].join('\n'),
  },
  {
    name: 'src/util/math.js',
    content: 'export const sum = (a, b) => a + b;\n',                // 0 findings
  },
];

// The flat tree the backend captures at scan time (dirs + files).
const FILE_TREE = [
  { path: 'src', type: 'dir' },
  { path: 'src/index.js', type: 'file' },
  { path: 'src/config', type: 'dir' },
  { path: 'src/config/secrets.js', type: 'file' },
  { path: 'src/util', type: 'dir' },
  { path: 'src/util/math.js', type: 'file' },
];

// --- run the REAL scanner per file, exactly like runProjectScan does --------
// entropy disabled so counts are deterministic (pattern/static rules only).
const patternFindings = [];
for (const f of FILES) {
  const res = scanCode(f.content, { entropyEnabled: false });
  for (const finding of res.findings) {
    patternFindings.push({ ...finding, fileName: f.name });
  }
}

const report = buildRiskReport({ patternFindings });
const findings = report.findings;

// --- 2 & 3. per-file grouping + same-file independence ----------------------
const byFile = new Map();
for (const f of findings) byFile.set(f.fileName, (byFile.get(f.fileName) || 0) + 1);
eq(byFile.get('src/index.js'), 2, 'src/index.js has 2 independent findings (AWS + API key)');
eq(byFile.get('src/config/secrets.js'), 1, 'src/config/secrets.js has 1 finding (Stripe)');
eq(byFile.get('src/util/math.js'), undefined, 'clean file contributes 0 findings');
eq(report.totalFindings, 3, 'total findings across repo = 3');

// clicking a file shows ONLY that file's findings
const indexOnly = findings.filter((f) => f.fileName === 'src/index.js');
eq(indexOnly.length, 2, 'file filter returns only the selected file\'s findings');
assert(indexOnly.every((f) => f.fileName === 'src/index.js'), 'file filter never leaks other files');

// the two same-file findings are genuinely distinct (different line AND type)
const [a, b] = indexOnly.sort((x, y) => x.line - y.line);
assert(a.line !== b.line, 'same-file findings are on different lines');
assert(a.type !== b.type, 'same-file findings are different vulnerability types');
const keys = new Set(findings.map((f, i) => findingKey(f, i)));
eq(keys.size, findings.length, 'every finding has a unique key (independent rows)');

// --- 4 & 5. exact red/green line-highlight math on REAL snippets ------------
for (const f of findings) {
  const start = codeStartLine(f);
  eq(start, Math.max(1, (f.line || 1) - 1), `startLine for ${f.fileName}:${f.line} is line-1 (static snippet)`);

  const { vulnMarks, corrMarks } = diffLines(f.vulnerableCode, f.correctedCode);
  eq(vulnMarks.length, corrMarks.length, `equal-length diff for ${f.fileName}:${f.line}`);

  const changed = vulnMarks.map((m, i) => ({ i, changed: m.changed })).filter((m) => m.changed);
  eq(changed.length, 1, `exactly one changed line for ${f.fileName}:${f.line}`);
  eq(start + changed[0].i, f.line, `the highlighted line number equals finding.line for ${f.fileName}:${f.line}`);

  // the corrected line must actually differ from the vulnerable one (a real fix)
  assert(
    vulnMarks[changed[0].i].text !== corrMarks[changed[0].i].text,
    `green fix differs from red vulnerable line for ${f.fileName}:${f.line}`,
  );
  // and the fix should no longer contain the raw secret literal
  assert(/process\.env|os\.getenv/.test(corrMarks[changed[0].i].text),
    `fix replaces the hardcoded secret with an env lookup for ${f.fileName}:${f.line}`);
}

// --- 6. deterministic security score from real severities -------------------
// 3 Critical -> penalty = min(51, 3*17)=51 -> score 49.
eq(report.criticalCount, 3, 'three Critical findings detected');
eq(report.highCount, 0, 'no High findings');
eq(report.securityScore, 49, 'security score = 100 - 51 = 49 (deterministic)');
eq(report.riskScore, 51, 'risk score = 100 - securityScore');
assert(report.securityScore >= 0 && report.securityScore <= 100, 'security score is within [0,100]');

// --- 7. severity filtering ---------------------------------------------------
const crit = findings.filter((f) => normSev(f.severity) === 'Critical');
eq(crit.length, 3, 'severity filter (Critical) returns exactly the 3 criticals');
assert(crit.every((f) => sevMeta(f.severity).color === '#ff3c5f'), 'critical severity maps to the red palette color');

// --- 8. file tree + folder roll-up ------------------------------------------
const { count } = computeTreeAggregates(findings);
eq(count.get('src/index.js'), 2, 'tree: file badge count = own findings (index.js)');
eq(count.get('src/config/secrets.js'), 1, 'tree: file badge count = own findings (secrets.js)');
eq(count.get('src'), 3, 'tree: folder src aggregates all 3 descendant findings');
eq(count.get('src/config'), 1, 'tree: folder src/config aggregates its 1 finding');
eq(count.get('src/util'), undefined, 'tree: clean folder src/util has no badge');

const root = buildFileTree(FILE_TREE);
const top = sortedChildren(root);
eq(top.length, 1, 'tree root has a single top-level entry (src)');
eq(top[0].name, 'src', 'top-level entry is the src folder');
const srcChildren = sortedChildren(top[0]);
eq(srcChildren.length, 3, 'src has three children (config, util, index.js)');
eq(srcChildren[0].type, 'dir', 'directories are sorted before files');
eq(srcChildren[srcChildren.length - 1].name, 'index.js', 'the file sorts after the folders');

// worst-severity rank rolls up too (Critical == rank 0)
const { topRank } = computeTreeAggregates(findings);
eq(topRank.get('src'), SEV_ORDER.Critical, 'folder inherits its worst descendant severity');

// --- summary ----------------------------------------------------------------
console.log('');
if (failures.length === 0) {
  console.log(`✅ ALL ${passed} ASSERTIONS PASSED — repository-details data flow is real end-to-end.`);
  process.exit(0);
} else {
  console.log(`❌ ${failures.length} FAILED, ${passed} passed:`);
  for (const m of failures) console.log('   - ' + m);
  process.exit(1);
}
