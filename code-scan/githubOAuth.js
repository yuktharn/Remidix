// githubOAuth.js
// Handles GitHub OAuth 2.0 authentication flow and token management

const crypto = require("crypto");
const { encryptToken, decryptToken } = require("./tokenCrypto");
const pool = require("./db");

// GitHub OAuth configuration
const GITHUB_OAUTH_CONFIG = {
  clientId: process.env.GITHUB_CLIENT_ID || "",
  clientSecret: process.env.GITHUB_CLIENT_SECRET || "",
  redirectUri: process.env.GITHUB_REDIRECT_URI || "http://localhost:3000/auth/github/callback",
  scopes: ["repo", "user", "read:user", "workflow"],
};

// Generate OAuth state token for CSRF protection
function generateState() {
  return crypto.randomBytes(32).toString("hex");
}

// Validate state token (for CSRF protection)
function validateState(storedState, incomingState) {
  if (!storedState || !incomingState) return false;
  return storedState === incomingState;
}

// Generate GitHub OAuth login URL
function generateGithubAuthUrl() {
  const state = generateState();

  const params = new URLSearchParams({
    client_id: GITHUB_OAUTH_CONFIG.clientId,
    redirect_uri: GITHUB_OAUTH_CONFIG.redirectUri,
    scope: GITHUB_OAUTH_CONFIG.scopes.join(" "),
    state: state,
    allow_signup: "true",
  });

  return {
    authUrl: `https://github.com/login/oauth/authorize?${params.toString()}`,
    state: state, // Return state to frontend
  };
}

// Exchange GitHub auth code for access token
async function exchangeCodeForToken(code, state, storedState) {
  try {
    // Validate CSRF state
    if (!validateState(storedState, state)) {
      throw new Error("Invalid state parameter. CSRF check failed.");
    }

    // Exchange code for access token
    const response = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        client_id: GITHUB_OAUTH_CONFIG.clientId,
        client_secret: GITHUB_OAUTH_CONFIG.clientSecret,
        code: code,
        redirect_uri: GITHUB_OAUTH_CONFIG.redirectUri,
      }),
    });

    if (!response.ok) {
      throw new Error(`GitHub OAuth failed: ${response.statusText}`);
    }

    const data = await response.json();

    if (data.error) {
      throw new Error(`GitHub OAuth error: ${data.error_description || data.error}`);
    }

    return {
      accessToken: data.access_token,
      tokenType: data.token_type || "bearer",
      scope: data.scope,
    };
  } catch (error) {
    console.error("Error exchanging code for token:", error);
    throw error;
  }
}

// Fetch GitHub user information
async function fetchGithubUser(accessToken) {
  try {
    const response = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
      },
    });

    if (!response.ok) {
      throw new Error(`Failed to fetch GitHub user: ${response.statusText}`);
    }

    return await response.json();
  } catch (error) {
    console.error("Error fetching GitHub user:", error);
    throw error;
  }
}

// Store user in database
async function storeUser(githubUser) {
  try {
    const [existing] = await pool.query(
      "SELECT id FROM users WHERE github_id = ?",
      [githubUser.id]
    );

    let userId;

    if (existing.length > 0) {
      userId = existing[0].id;
      // Update user info
      await pool.query(
        "UPDATE users SET username = ?, avatar_url = ?, updated_at = NOW() WHERE github_id = ?",
        [githubUser.login, githubUser.avatar_url, githubUser.id]
      );
    } else {
      // Create new user
      const [result] = await pool.query(
        "INSERT INTO users (github_id, email, username, avatar_url, created_at) VALUES (?, ?, ?, ?, NOW())",
        [githubUser.id, githubUser.email, githubUser.login, githubUser.avatar_url]
      );
      userId = result.insertId;
    }

    return userId;
  } catch (error) {
    console.error("Error storing user:", error);
    throw error;
  }
}

// Store GitHub token in database (encrypted)
async function storeGithubToken(userId, accessToken) {
  try {
    const enc = encryptToken(accessToken);
    const encryptedToken = JSON.stringify({ e: enc.encrypted, iv: enc.iv, tag: enc.authTag });

    // Check if user has an existing GitHub token
    const [existing] = await pool.query(
      "SELECT id FROM github_tokens WHERE user_id = ?",
      [userId]
    );

    if (existing.length > 0) {
      // Update existing token
      await pool.query(
        "UPDATE github_tokens SET encrypted_token = ?, updated_at = NOW() WHERE user_id = ?",
        [encryptedToken, userId]
      );
    } else {
      // Insert new token
      await pool.query(
        "INSERT INTO github_tokens (user_id, encrypted_token, created_at, updated_at) VALUES (?, ?, NOW(), NOW())",
        [userId, encryptedToken]
      );
    }

    return true;
  } catch (error) {
    console.error("Error storing GitHub token:", error);
    throw error;
  }
}

// Retrieve GitHub token from database (decrypted)
async function getGithubToken(userId) {
  try {
    const [rows] = await pool.query(
      "SELECT encrypted_token FROM github_tokens WHERE user_id = ?",
      [userId]
    );

    if (rows.length === 0) {
      return null; // No token stored
    }

    const raw = rows[0].encrypted_token;
    try {
      const parsed = JSON.parse(raw);
      const decryptedToken = decryptToken(parsed.e, parsed.iv, parsed.tag);
      return decryptedToken;
    } catch {
      // Legacy format: treat raw as plain token (unencrypted)
      return raw;
    }
  } catch (error) {
    console.error("Error retrieving GitHub token:", error);
    throw error;
  }
}

// Check if token is valid (test API call)
async function validateGithubToken(accessToken) {
  try {
    const response = await fetch("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        Accept: "application/vnd.github+json",
      },
    });

    return response.ok;
  } catch (error) {
    console.error("Error validating GitHub token:", error);
    return false;
  }
}

// Revoke GitHub token (delete from database)
async function revokeGithubToken(userId) {
  try {
    await pool.query("DELETE FROM github_tokens WHERE user_id = ?", [userId]);
    return true;
  } catch (error) {
    console.error("Error revoking GitHub token:", error);
    throw error;
  }
}

// List user's GitHub repositories (with pagination)
async function listGithubRepos(accessToken, page = 1, perPage = 30) {
  try {
    const response = await fetch(
      `https://api.github.com/user/repos?page=${page}&per_page=${perPage}&sort=updated&direction=desc&affiliation=owner,collaborator`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch repos: ${response.statusText}`);
    }

    const repos = await response.json();
    const linkHeader = response.headers.get("link");
    const hasNextPage = linkHeader && linkHeader.includes('rel="next"');

    return {
      repos: repos.map((repo) => ({
        id: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        url: repo.html_url,
        description: repo.description,
        isPrivate: repo.private,
        language: repo.language,
        starsCount: repo.stargazers_count,
        defaultBranch: repo.default_branch,
        updatedAt: repo.updated_at,
        owner: repo.owner.login,
      })),
      hasNextPage,
      nextPage: hasNextPage ? page + 1 : null,
      totalCount: repos.length,
    };
  } catch (error) {
    console.error("Error listing GitHub repos:", error);
    throw error;
  }
}

// Get repository branches
async function getGithubBranches(accessToken, owner, repo) {
  try {
    const response = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/branches`,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          Accept: "application/vnd.github+json",
        },
      }
    );

    if (!response.ok) {
      throw new Error(`Failed to fetch branches: ${response.statusText}`);
    }

    const branches = await response.json();
    return branches.map((branch) => ({
      name: branch.name,
      commit: branch.commit.sha,
      isDefault: branch.name === "main" || branch.name === "master",
    }));
  } catch (error) {
    console.error("Error fetching branches:", error);
    throw error;
  }
}

// Get current user info
async function getCurrentUser(userId) {
  try {
    const [rows] = await pool.query(
      "SELECT id, github_id, email, username, avatar_url FROM users WHERE id = ?",
      [userId]
    );

    if (rows.length === 0) {
      return null;
    }

    return {
      id: rows[0].id,
      githubId: rows[0].github_id,
      email: rows[0].email,
      username: rows[0].username,
      avatarUrl: rows[0].avatar_url,
    };
  } catch (error) {
    console.error("Error fetching user:", error);
    throw error;
  }
}

// Check repository ownership and permissions
async function checkRepoOwnership(accessToken, owner, repo) {
  try {
    const userRes = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
    });
    if (!userRes.ok) throw new Error("Failed to fetch authenticated user");
    const user = await userRes.json();

    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
    });
    if (!repoRes.ok) throw new Error(`Repository ${owner}/${repo} not found or inaccessible`);
    const repoData = await repoRes.json();

    return {
      authenticatedUser: user.login,
      isOwner: repoData.owner?.login === user.login,
      hasPushAccess: Boolean(repoData.permissions?.push || repoData.permissions?.admin || repoData.owner?.login === user.login),
      defaultBranch: repoData.default_branch || "main",
      repoPrivate: repoData.private,
      repoFullName: repoData.full_name,
    };
  } catch (error) {
    console.error("Error checking repo ownership:", error);
    throw error;
  }
}

// Check if a fork already exists for the authenticated user
async function checkExistingFork(accessToken, owner, repo) {
  try {
    const userRes = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
    });
    if (!userRes.ok) throw new Error("Failed to fetch authenticated user");
    const user = await userRes.json();

    const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
    });
    if (!repoRes.ok) throw new Error(`Repository ${owner}/${repo} not found`);
    const repoData = await repoRes.json();

    const forkFullName = `${user.login}/${repo}`;
    const forkRes = await fetch(`https://api.github.com/repos/${forkFullName}`, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
    });

    if (forkRes.ok) {
      const forkData = await forkRes.json();
      return {
        forkExists: true,
        forkOwner: user.login,
        forkRepo: forkData.name,
        forkFullName: forkData.full_name,
        forkUrl: forkData.html_url,
        forkDefaultBranch: forkData.default_branch || "main",
        forkedAt: forkData.created_at,
        sourceFullName: repoData.full_name,
      };
    }

    return { forkExists: false, authenticatedUser: user.login };
  } catch (error) {
    console.error("Error checking fork:", error);
    throw error;
  }
}

// Create a fork of a repository
async function createFork(accessToken, owner, repo) {
  try {
    const userRes = await fetch("https://api.github.com/user", {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
    });
    if (!userRes.ok) throw new Error("Failed to fetch authenticated user");
    const user = await userRes.json();

    const forkRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/forks`, {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
    });

    if (!forkRes.ok) {
      const errBody = await forkRes.text();
      if (forkRes.status === 422) {
        return { forkExists: true, forkOwner: user.login, forkRepo: repo, forkFullName: `${user.login}/${repo}`, message: "Fork already exists" };
      }
      throw new Error(`Fork creation failed (${forkRes.status}): ${errBody.slice(0, 200)}`);
    }

    const forkData = await forkRes.json();
    return {
      forkExists: false,
      forkCreated: true,
      forkOwner: forkData.owner?.login || user.login,
      forkRepo: forkData.name || repo,
      forkFullName: forkData.full_name || `${user.login}/${repo}`,
      forkUrl: forkData.html_url,
      forkDefaultBranch: forkData.default_branch || "main",
      createdAt: forkData.created_at,
    };
  } catch (error) {
    console.error("Error creating fork:", error);
    throw error;
  }
}

// Wait for fork to be available (GitHub forks are async)
async function waitForFork(accessToken, forkOwner, forkRepo, maxWaitMs = 30000) {
  const startTime = Date.now();
  while (Date.now() - startTime < maxWaitMs) {
    try {
      const res = await fetch(`https://api.github.com/repos/${forkOwner}/${forkRepo}`, {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/vnd.github+json" },
      });
      if (res.ok) {
        const data = await res.json();
        if (data.full_name) return { ready: true, forkFullName: data.full_name, defaultBranch: data.default_branch };
      }
    } catch { /* retry */ }
    await new Promise(r => setTimeout(r, 2000));
  }
  throw new Error(`Fork ${forkOwner}/${forkRepo} not available after ${maxWaitMs / 1000}s. The fork may still be processing — try again in a minute.`);
}

module.exports = {
  GITHUB_OAUTH_CONFIG,
  generateGithubAuthUrl,
  exchangeCodeForToken,
  fetchGithubUser,
  storeUser,
  storeGithubToken,
  getGithubToken,
  validateGithubToken,
  revokeGithubToken,
  listGithubRepos,
  getGithubBranches,
  getCurrentUser,
  generateState,
  validateState,
  checkRepoOwnership,
  checkExistingFork,
  createFork,
  waitForFork,
};
