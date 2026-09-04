// vulnLogic.js
// ---------------------------------------------------------------------------
// Pure, framework-free helpers shared by the repository-details UI
// (ProjectsPanel.jsx) and the offline logic test (test_repo_details.mjs).
//
// Keeping these here — instead of inline in the JSX — means the test exercises
// the EXACT code the UI runs, so the red/green line-highlight math, the file
// tree and the severity aggregation can never silently drift from what ships.
//
// Everything is derived from the real finding objects the scanners emit
// ({ fileName, line, severity, vulnerableCode, correctedCode, method, ... }).
// Nothing here is mocked or hard-coded.
// ---------------------------------------------------------------------------

// Severity presentation + canonical ordering. Colors match the app palette.
export const SEV_META = {
  Critical: { color: '#ff3c5f', bg: 'rgba(255,60,95,0.14)', border: 'rgba(255,60,95,0.42)', dot: '#e2504a' },
  High:     { color: '#e8a33d', bg: 'rgba(232,163,61,0.14)', border: 'rgba(232,163,61,0.42)', dot: '#e8a33d' },
  Medium:   { color: '#d9c94f', bg: 'rgba(217,201,79,0.14)', border: 'rgba(217,201,79,0.42)', dot: '#d9c94f' },
  Low:      { color: '#4fd08a', bg: 'rgba(79,208,138,0.14)', border: 'rgba(79,208,138,0.42)', dot: '#4fd08a' },
  Info:     { color: '#8a8f9c', bg: 'rgba(138,143,156,0.14)', border: 'rgba(138,143,156,0.42)', dot: '#8a8f9c' },
};

export const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };

export function normSev(s) {
  const t = String(s || '').toLowerCase();
  if (t.startsWith('crit')) return 'Critical';
  if (t.startsWith('high')) return 'High';
  if (t.startsWith('med')) return 'Medium';
  if (t.startsWith('low')) return 'Low';
  if (t.startsWith('info')) return 'Info';
  return 'Medium';
}

export function sevMeta(s) { return SEV_META[normSev(s)] || SEV_META.Info; }

// The first source line shown in a finding's snippet. The static detectors
// build the snippet with one line of context before the match
// (extractCodeSnippet(lines, line, 1) => starts at max(1, line-1)); the LLM and
// dependency findings anchor exactly at `line`.
export function codeStartLine(f) {
  const m = String(f.method || '').toLowerCase();
  if (m === 'pattern' || m === 'static' || m === 'entropy') return Math.max(1, (f.line || 1) - 1);
  return f.line || 1;
}

// Data-driven line diff: a line is "changed" (highlighted red on the left,
// green on the right) exactly when the two snippets differ at that position.
// Everything else renders as unchanged context. This highlights precisely the
// real vulnerable line(s) and their exact fix — never a guessed line.
export function diffLines(vulnerable, corrected) {
  const a = String(vulnerable || '').replace(/\r/g, '').replace(/\n$/, '').split('\n');
  const b = String(corrected || '').replace(/\r/g, '').replace(/\n$/, '').split('\n');
  const max = Math.max(a.length, b.length);
  const vulnMarks = [];
  const corrMarks = [];
  for (let i = 0; i < max; i++) {
    // Use a sentinel for "missing line" so a real empty string on one side and
    // an absent line on the other are still treated as a change.
    const av = i < a.length ? a[i] : ' ';
    const bv = i < b.length ? b[i] : ' ';
    const changed = av !== bv;
    if (i < a.length) vulnMarks.push({ text: a[i], changed });
    if (i < b.length) corrMarks.push({ text: b[i], changed });
  }
  return { vulnMarks, corrMarks };
}

// Stable identity for a finding so React keys and the open-accordion state
// survive re-renders and keep same-file issues independent.
export function findingKey(f, idx) {
  return `${f.fileName || 'src'}:${f.line || 0}:${f.type || 'issue'}:${idx}`;
}

// Every path prefix of a file, e.g. "src/api/users.js" ->
// ["src", "src/api", "src/api/users.js"].
export function prefixesOf(path) {
  const parts = path.split('/');
  const out = [];
  let acc = '';
  for (const p of parts) { acc = acc ? `${acc}/${p}` : p; out.push(acc); }
  return out;
}

// For every finding, credit its file AND each ancestor folder with a count and
// the most-severe rank seen. Lets folders show an aggregate badge and files
// show their own real count.
export function computeTreeAggregates(findings) {
  const count = new Map();
  const topRank = new Map();
  for (const f of findings) {
    if (!f.fileName) continue;
    const rank = SEV_ORDER[normSev(f.severity)] ?? 4;
    for (const p of prefixesOf(f.fileName)) {
      count.set(p, (count.get(p) || 0) + 1);
      topRank.set(p, Math.min(topRank.has(p) ? topRank.get(p) : 99, rank));
    }
  }
  return { count, topRank };
}

// Build a nested tree from the flat [{ path, type }] list captured at scan time.
export function buildFileTree(paths) {
  const root = { name: '', path: '', type: 'dir', children: {} };
  for (const entry of paths) {
    if (!entry || !entry.path) continue;
    const parts = entry.path.split('/');
    let node = root;
    let acc = '';
    parts.forEach((part, i) => {
      acc = acc ? `${acc}/${part}` : part;
      const isLast = i === parts.length - 1;
      if (!node.children[part]) {
        node.children[part] = { name: part, path: acc, type: isLast ? entry.type : 'dir', children: {} };
      } else if (!isLast) {
        node.children[part].type = 'dir';
      }
      node = node.children[part];
    });
  }
  return root;
}

// dirs first, then files; alphabetical within each group.
export function sortedChildren(node) {
  return Object.values(node.children).sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1;
    return a.name.localeCompare(b.name);
  });
}
