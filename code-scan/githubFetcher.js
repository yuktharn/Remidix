// githubFetcher.js
// Fetches source files AND the full file/folder tree from a GitHub or GitLab
// repository so they can be fed into the existing scanCode pipeline and
// rendered as a real, expandable repository tree in the UI.
//
// Public repositories: works with NO token — the Authorization/PRIVATE-TOKEN
// header is simply omitted, so we hit the provider's public, unauthenticated
// API (subject to that provider's anonymous rate limits).
// Private repositories: a token with read access to the repo is required;
// if it's missing or invalid the provider's API returns 401/403/404, which
// callers surface to the user as "repository is private or inaccessible".
//
// WHAT CHANGED vs the previous version:
//   * Added fetchRepoSnapshot(): returns BOTH the scannable files (as before)
//     AND the complete repo tree ([{ path, type }]) in a single tree API call,
//     so the details page can show the real folder structure with per-file
//     vulnerability badges — no extra network round-trips.
//   * Added fetchRepoTree(): tree only.
//   * fetchRepoFiles() is unchanged in behaviour and signature (it now just
//     delegates to fetchRepoSnapshot and returns .files), so every existing
//     caller keeps working.

const GITHUB_URL_RE = /github\.com[/:]([^/]+)\/([^/.\s]+)/i;
const GITLAB_URL_RE = /gitlab\.com[/:]([^/]+)\/([^/.\s]+)/i;
const SOURCE_EXT_RE = /\.(js|jsx|mjs|cjs|ts|tsx|mts|cts|py|pyw|java|go|rb|php|rs|c|cpp|cc|cxx|h|hpp|hxx|cs|kt|kts|swift|html|htm|css|scss|sass|less|sql|sh|bash|zsh|yaml|yml|json|xml|toml|ini|conf)$/i;
const CONFIG_FILENAMES = new Set([
  'dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'package.json',
  'requirements.txt', 'pyproject.toml', 'pipfile', 'pom.xml', 'build.gradle',
  'build.gradle.kts', 'settings.gradle', 'gemfile', 'cargo.toml', 'cargo.lock',
  'go.mod', 'go.sum', 'composer.json', '.env.example', '.env.sample', '.env.template'
]);

function isScannableFile(path) {
  if (!path) return false;
  const baseName = path.split('/').pop().toLowerCase();
  if (CONFIG_FILENAMES.has(baseName) || baseName.startsWith('dockerfile') || baseName.startsWith('docker-compose')) return true;
  return SOURCE_EXT_RE.test(path);
}

const SKIP_DIR = /(^|\/)(node_modules|dist|build|\.git|coverage|\.next|\.nuxt|vendor|target|bin|obj)(\/|$)/i;
const MAX_FILES = 300;            // files actually fetched + scanned
const MAX_TREE_ENTRIES = 5000;    // paths returned for the UI tree
const MAX_FILE_BYTES = 250_000;
const REQUEST_TIMEOUT_MS = 15_000; // fail fast instead of hanging the caller


async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error(`Request to ${url} timed out after ${REQUEST_TIMEOUT_MS}ms`);
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

function detectPlatform(url) {
  if (GITLAB_URL_RE.test(url)) return "gitlab";
  if (GITHUB_URL_RE.test(url)) return "github";
  throw new Error(
    `Could not determine the platform for "${url}". Only github.com and gitlab.com repository URLs are supported.`
  );
}

function parseRepoUrl(url) {
  const platform = detectPlatform(url);
  const re = platform === "gitlab" ? GITLAB_URL_RE : GITHUB_URL_RE;
  const m = url.match(re);
  if (!m) throw new Error(`Could not parse owner/repo from "${url}"`);
  return { platform, owner: m[1], repo: m[2].replace(/\.git$/, "") };
}

// Normalises a raw provider tree into the compact shape the UI expects.
// Keeps every path (files AND folders) except build/vendor noise, capped so a
// giant monorepo can't produce a multi-megabyte response.
function normaliseTree(entries) {
  const out = [];
  for (const n of entries) {
    if (!n.path || SKIP_DIR.test(n.path)) continue;
    out.push({
      path: n.path,
      type: n.type === "tree" ? "dir" : "file",
      size: typeof n.size === "number" ? n.size : null,
    });
    if (out.length >= MAX_TREE_ENTRIES) break;
  }
  return out;
}

// ---------------------------------------------------------------------
// GitHub
// ---------------------------------------------------------------------

async function ghFetch(path, token) {
  const headers = { Accept: "application/vnd.github+json" };
  // Only attach Authorization when a real token was provided. Sending
  // "Bearer undefined"/"Bearer " makes GitHub reject even public repo
  // requests with 401, which was the root cause of public repos failing.
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetchWithTimeout(`https://api.github.com${path}`, { headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`GitHub API ${res.status} on ${path}: ${body.slice(0, 200)}`);
  }
  return res.json();
}

async function fetchGithubSnapshot(owner, repo, branch, token) {
  const tree = await ghFetch(
    `/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
    token
  );

  const entries = tree.tree || [];
  const treeList = normaliseTree(entries);
  const treeTruncated = Boolean(tree.truncated) || entries.length > MAX_TREE_ENTRIES;

  const candidates = entries
    .filter((n) => n.type === "blob")
    .filter((n) => isScannableFile(n.path) && !SKIP_DIR.test(n.path))
    .slice(0, MAX_FILES);

  const files = await Promise.all(
    candidates.map(async (n) => {
      try {
        const blob = await ghFetch(`/repos/${owner}/${repo}/git/blobs/${n.sha}`, token);
        if (blob.size > MAX_FILE_BYTES) return null;
        const content = Buffer.from(blob.content, blob.encoding || "base64").toString("utf-8");
        return { name: n.path, content };
      } catch {
        return null; // skip unreadable/binary files, don't fail the whole scan
      }
    })
  );

  return { files: files.filter(Boolean), tree: treeList, treeTruncated };
}

// ---------------------------------------------------------------------
// GitLab
// ---------------------------------------------------------------------

async function glFetch(path, token) {
  const headers = {};
  // Same principle as GitHub: only attach the token header when we have
  // one, so public projects work fully unauthenticated.
  if (token) headers["PRIVATE-TOKEN"] = token;

  const res = await fetchWithTimeout(`https://gitlab.com/api/v4${path}`, { headers });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`GitLab API ${res.status} on ${path}: ${body.slice(0, 200)}`);
  }
  return res.json();
}

// GitLab caps a tree page at 100 entries, so page through until we have the
// whole tree (bounded by MAX_TREE_ENTRIES). Uses the X-Next-Page header.
async function glFetchTree(projectId, branch, token) {
  const headers = {};
  if (token) headers["PRIVATE-TOKEN"] = token;

  const all = [];
  let page = 1;
  let truncated = false;

  while (page && all.length < MAX_TREE_ENTRIES) {
    const res = await fetchWithTimeout(
      `https://gitlab.com/api/v4/projects/${projectId}/repository/tree` +
        `?ref=${encodeURIComponent(branch)}&recursive=true&per_page=100&page=${page}`,
      { headers }
    );
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`GitLab API ${res.status} on tree: ${body.slice(0, 200)}`);
    }
    const batch = await res.json();
    if (Array.isArray(batch)) all.push(...batch);

    const next = res.headers.get("x-next-page");
    page = next ? Number(next) : 0;
    if (page && all.length >= MAX_TREE_ENTRIES) truncated = true;
  }

  return { entries: all, truncated };
}

async function fetchGitlabSnapshot(owner, repo, branch, token) {
  const projectId = encodeURIComponent(`${owner}/${repo}`);

  const { entries, truncated } = await glFetchTree(projectId, branch, token);
  const treeList = normaliseTree(entries);
  const treeTruncated = truncated || entries.length > MAX_TREE_ENTRIES;

  const candidates = entries
    .filter((n) => n.type === "blob")
    .filter((n) => isScannableFile(n.path) && !SKIP_DIR.test(n.path))
    .slice(0, MAX_FILES);

  const files = await Promise.all(
    candidates.map(async (n) => {
      try {
        const filePath = encodeURIComponent(n.path);
        const headers = {};
        if (token) headers["PRIVATE-TOKEN"] = token;

        const res = await fetchWithTimeout(
          `https://gitlab.com/api/v4/projects/${projectId}/repository/files/${filePath}/raw?ref=${encodeURIComponent(branch)}`,
          { headers }
        );
        if (!res.ok) return null;

        const content = await res.text();
        if (Buffer.byteLength(content, "utf-8") > MAX_FILE_BYTES) return null;
        return { name: n.path, content };
      } catch {
        return null; // skip unreadable/binary files, don't fail the whole scan
      }
    })
  );

  return { files: files.filter(Boolean), tree: treeList, treeTruncated };
}

// ---------------------------------------------------------------------
// Public entrypoints
// ---------------------------------------------------------------------

// Returns { files: [{ name, content }], tree: [{ path, type, size }], treeTruncated }.
// `token` is OPTIONAL: pass null/undefined/"" for public repositories.
async function fetchRepoSnapshot(repoUrl, branch, token) {
  const { platform, owner, repo } = parseRepoUrl(repoUrl);
  const effectiveToken = token && String(token).trim() ? String(token).trim() : null;
  const effectiveBranch = branch || "main";

  if (platform === "gitlab") {
    return fetchGitlabSnapshot(owner, repo, effectiveBranch, effectiveToken);
  }
  return fetchGithubSnapshot(owner, repo, effectiveBranch, effectiveToken);
}

// Backwards-compatible: returns just the scannable files array, exactly like before.
async function fetchRepoFiles(repoUrl, branch, token) {
  const { files } = await fetchRepoSnapshot(repoUrl, branch, token);
  return files;
}

// Tree only ([{ path, type, size }]) — handy for a lightweight refresh.
async function fetchRepoTree(repoUrl, branch, token) {
  const { tree } = await fetchRepoSnapshot(repoUrl, branch, token);
  return tree;
}

module.exports = { fetchRepoFiles, fetchRepoSnapshot, fetchRepoTree, parseRepoUrl };
