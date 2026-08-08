const REPO_URL_RE = /github\.com[/:]([^/]+)\/([^/.\s]+)/i;
const SOURCE_EXT = /\.(js|jsx|ts|tsx|py|java|go|rb|php|env|json|yml|yaml)$/i;
const SKIP_DIR = /(^|\/)(node_modules|dist|build|\.git|coverage)(\/|$)/;
const MAX_FILES = 40;
const MAX_FILE_BYTES = 100_000;

function parseRepoUrl(url) {
  const m = url.match(REPO_URL_RE);
  if (!m) throw new Error(`Could not parse owner/repo from "${url}"`);
  return { owner: m[1], repo: m[2].replace(/\.git$/, "") };
}

async function ghFetch(path, token) {
  const res = await fetch(`https://api.github.com${path}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`GitHub API ${res.status} on ${path}: ${body.slice(0, 200)}`);
  }
  return res.json();
}

// Returns [{ name, content }] ready to feed into your existing scanCode pipeline.
async function fetchRepoFiles(repoUrl, branch, token) {
  const { owner, repo } = parseRepoUrl(repoUrl);

  const tree = await ghFetch(
    `/repos/${owner}/${repo}/git/trees/${branch}?recursive=1`,
    token
  );

  const candidates = (tree.tree || [])
    .filter((n) => n.type === "blob")
    .filter((n) => SOURCE_EXT.test(n.path) && !SKIP_DIR.test(n.path))
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

  return files.filter(Boolean);
}

module.exports = { fetchRepoFiles, parseRepoUrl };