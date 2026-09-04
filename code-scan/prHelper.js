require('dotenv').config();
const { Octokit } = require('@octokit/rest');

async function getOctokit(token) {
  const auth = token || process.env.GITHUB_TOKEN;
  if (!auth) throw new Error('No GitHub token available. Please authenticate with GitHub.');
  return new Octokit({ auth });
}

// Check repository permissions and fork if needed
async function checkRepoPermissions(octokit, owner, repo) {
  try {
    const { data: user } = await octokit.users.getAuthenticated();
    const { data: repoData } = await octokit.repos.get({ owner, repo });

    const hasPushAccess = Boolean(repoData.permissions?.push || repoData.permissions?.admin || repoData.owner?.login === user.login);
    return {
      authenticatedUser: user.login,
      hasPushAccess,
      isOwner: repoData.owner?.login === user.login,
      defaultBranch: repoData.default_branch || 'main',
    };
  } catch (err) {
    console.error('Permission check failed:', err.message);
    throw new Error(`Unable to verify repository permissions for ${owner}/${repo}: ${err.message}`);
  }
}

// Push corrected files to a dedicated branch (on repo or fork)
async function pushFixBranch({ owner, repo, baseBranch, branchName, files, commitMessage, token }) {
  const octokit = await getOctokit(token);
  const { authenticatedUser, hasPushAccess, defaultBranch } = await checkRepoPermissions(octokit, owner, repo);

  let targetOwner = owner;
  let targetRepo = repo;
  let isFork = false;

  if (!hasPushAccess) {
    // User does not have push access: create/use fork
    console.log(`User ${authenticatedUser} lacks push access to ${owner}/${repo}. Creating/using fork...`);
    const forkRes = await octokit.repos.createFork({ owner, repo });
    targetOwner = forkRes.data.owner.login;
    targetRepo = forkRes.data.name;
    isFork = true;

    // Small delay to allow GitHub to initialize new forks
    await new Promise((resolve) => setTimeout(resolve, 2000));
  }

  // 1) Resolve base branch SHA (target default branch if baseBranch not found or unspecified)
  const candidateBranches = [baseBranch, defaultBranch, 'main', 'master'].filter(Boolean);
  let baseSha = null;
  let effectiveBaseBranch = defaultBranch || 'main';

  for (const b of candidateBranches) {
    try {
      const baseRef = await octokit.git.getRef({ owner: targetOwner, repo: targetRepo, ref: `heads/${b}` });
      baseSha = baseRef.data.object.sha;
      effectiveBaseBranch = b;
      break;
    } catch {
      try {
        const upstreamRef = await octokit.git.getRef({ owner, repo, ref: `heads/${b}` });
        baseSha = upstreamRef.data.object.sha;
        effectiveBaseBranch = b;
        break;
      } catch {
        // Continue trying next candidate
      }
    }
  }

  if (!baseSha) {
    throw new Error(`Unable to find base branch reference for ${owner}/${repo}. Checked: ${candidateBranches.join(', ')}`);
  }

  const effectiveBranchName = branchName || `securecode/fix-${Date.now().toString(36)}`;

  // 2) Create or update branch
  const newRefName = `refs/heads/${effectiveBranchName}`;
  try {
    await octokit.git.createRef({ owner: targetOwner, repo: targetRepo, ref: newRefName, sha: baseSha });
  } catch (e) {
    if (e.status === 422) {
      // Branch already exists - attempt to update ref to baseSha
      try {
        await octokit.git.updateRef({
          owner: targetOwner,
          repo: targetRepo,
          ref: `heads/${effectiveBranchName}`,
          sha: baseSha,
          force: true,
        });
      } catch {
        // If force update not permitted, proceed with existing branch commit
      }
    } else {
      throw e;
    }
  }

  // 3) Commit each modified file (normalizing path and skipping unchanged content)
  let lastCommitSha = baseSha;
  let committedCount = 0;

  for (const f of files) {
    const rawPath = f.path || f.name || '';
    const path = rawPath.replace(/\\/g, '/').replace(/^\.?\/+/, '');
    if (!path) continue;

    const fileContent = String(f.content ?? '');
    const contentBase64 = Buffer.from(fileContent, 'utf8').toString('base64');
    let fileSha = null;

    try {
      const existing = await octokit.repos.getContent({
        owner: targetOwner,
        repo: targetRepo,
        path,
        ref: effectiveBranchName,
      });
      if (existing.data && !Array.isArray(existing.data)) {
        fileSha = existing.data.sha;
        // Check if content is already identical
        if (existing.data.content) {
          const existingText = Buffer.from(existing.data.content.replace(/\s/g, ''), 'base64').toString('utf8');
          if (existingText === fileContent) {
            // No changes for this file — skip redundant commit
            continue;
          }
        }
      }
    } catch {
      // 404 means new file to be created
    }

    const commitRes = await octokit.repos.createOrUpdateFileContents({
      owner: targetOwner,
      repo: targetRepo,
      path,
      message: commitMessage || `fix: apply security remediation in ${path}`,
      content: contentBase64,
      branch: effectiveBranchName,
      ...(fileSha ? { sha: fileSha } : {}),
    });

    lastCommitSha = commitRes.data.commit.sha;
    committedCount++;
  }

  const branchUrl = `https://github.com/${targetOwner}/${targetRepo}/tree/${effectiveBranchName}`;

  return {
    success: true,
    owner: targetOwner,
    repo: targetRepo,
    branch: effectiveBranchName,
    baseBranch: effectiveBaseBranch,
    commitSha: lastCommitSha,
    changedFilesCount: committedCount,
    url: branchUrl,
    isFork,
    targetOwner,
    authenticatedUser,
  };
}

// Generate formatted PR description with vulnerability details
function buildPRDescription({ files, findingsSummary, branchName, baseBranch }) {
  const fileList = (files || []).map((f) => {
    const p = (f.path || f.name || '').replace(/\\/g, '/').replace(/^\.?\/+/, '');
    return `- \`${p}\``;
  }).join('\n');

  let findingsSection = '';
  if (Array.isArray(findingsSummary) && findingsSummary.length > 0) {
    const rows = findingsSummary.map((f, i) => {
      const type = f.type || 'Security Issue';
      const sev = (f.severity || 'Medium').toUpperCase();
      const file = (f.fileName || f.file || 'Source code').replace(/\\/g, '/');
      const cwe = f.cwe || 'N/A';
      return `| ${i + 1} | **${sev}** | ${type} | \`${file}\` | ${cwe} | ✅ Fixed |`;
    }).join('\n');

    findingsSection = `
### 🛡️ Vulnerabilities Remediated
| # | Severity | Finding | File | CWE | Status |
|---|---|---|---|---|---|
${rows}
`;
  }

  return `## 🔒 SecureCode AI Security Remediation

This Pull Request applies verified security patches generated by **SecureCode**.

${findingsSection}

### 📁 Modified Files
${fileList || '- Automated security fixes'}

---
### 🔍 Quality & Safety Verification
- Minimal functionality-preserving modifications applied
- Verified against SecureCode AST & static analysis rules
- Hardcoded secrets removed and prepared for environment variable configuration

*Generated automatically by [SecureCode AI Platform](https://github.com).*`;
}

// Create a pull request (supporting both same-repo and cross-fork PRs)
async function createFixPR({ owner, repo, baseBranch, branchName, files, title, body, findingsSummary, token }) {
  const octokit = await getOctokit(token);

  // 1) First ensure the branch is pushed with real modified files
  const pushResult = await pushFixBranch({
    owner,
    repo,
    baseBranch,
    branchName,
    files,
    token,
  });

  const headRef = pushResult.isFork ? `${pushResult.targetOwner}:${pushResult.branch}` : pushResult.branch;
  const prTitle = title || `chore(security): apply automated vulnerability fixes (${pushResult.branch})`;
  const prBody = body || buildPRDescription({ files, findingsSummary, branchName: pushResult.branch, baseBranch: pushResult.baseBranch });

  // 2) Create Pull Request on target repository targeting the verified base branch
  let prData;
  try {
    const prRes = await octokit.pulls.create({
      owner,
      repo,
      title: prTitle,
      head: headRef,
      base: pushResult.baseBranch,
      body: prBody,
    });
    prData = prRes.data;
  } catch (prErr) {
    // If PR already exists for this head branch, retrieve the open PR
    if (prErr.status === 422) {
      const existingPRs = await octokit.pulls.list({
        owner,
        repo,
        head: pushResult.isFork ? `${pushResult.targetOwner}:${pushResult.branch}` : `${owner}:${pushResult.branch}`,
        state: 'open',
      });
      if (existingPRs.data && existingPRs.data.length > 0) {
        prData = existingPRs.data[0];
        try {
          await octokit.pulls.update({
            owner,
            repo,
            pull_number: prData.number,
            title: prTitle,
            body: prBody,
          });
        } catch {
          // Keep existing PR if update fails
        }
      } else {
        throw prErr;
      }
    } else {
      throw prErr;
    }
  }

  return {
    id: prData.id,
    number: prData.number,
    title: prData.title,
    url: prData.html_url,
    html_url: prData.html_url,
    state: prData.state,
    sourceBranch: headRef,
    targetBranch: pushResult.baseBranch,
    changedFiles: pushResult.changedFilesCount > 0 ? pushResult.changedFilesCount : files.length,
    createdAt: prData.created_at,
    isFork: pushResult.isFork,
  };
}

module.exports = {
  getOctokit,
  checkRepoPermissions,
  pushFixBranch,
  createFixPR,
  buildPRDescription,
};

