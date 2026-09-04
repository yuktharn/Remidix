// code-scan/githubWebhook.js
// Handle GitHub webhook events for CI/CD pipeline

const crypto = require('crypto');

class GitHubWebhookHandler {
  constructor(secret = process.env.GITHUB_WEBHOOK_SECRET) {
    this.secret = secret;
  }

  /**
   * Verify webhook signature
   * @param {string} payload - Raw request body
   * @param {string} signature - X-Hub-Signature-256 header
   * @returns {boolean}
   */
  verifySignature(payload, signature) {
    if (!this.secret) {
      console.warn('GITHUB_WEBHOOK_SECRET not configured - webhook verification disabled');
      return true;
    }

    const hash = crypto
      .createHmac('sha256', this.secret)
      .update(payload)
      .digest('hex');

    const expected = `sha256=${hash}`;
    return crypto.timingSafeEqual(expected, signature);
  }

  /**
   * Parse webhook event
   * @param {object} body - Parsed webhook body
   * @returns {object} event details
   */
  parseEvent(body) {
    const event = {
      type: null,
      action: null,
      repository: null,
      branch: null,
      commits: [],
      pullRequest: null,
      pusher: null,
    };

    // Detect event type
    if (body.ref && body.repository) {
      // Push event
      event.type = 'push';
      event.repository = body.repository.full_name;
      event.branch = body.ref.replace('refs/heads/', '');
      event.commits = body.commits || [];
      event.pusher = body.pusher?.name;
    } else if (body.pull_request) {
      // Pull request event
      event.type = 'pull_request';
      event.action = body.action; // opened, closed, synchronize, etc.
      event.repository = body.repository.full_name;
      event.pullRequest = {
        number: body.pull_request.number,
        title: body.pull_request.title,
        branch: body.pull_request.head.ref,
        baseBranch: body.pull_request.base.ref,
        url: body.pull_request.html_url,
        author: body.pull_request.user.login,
      };
    } else if (body.issue) {
      // Issue event
      event.type = 'issue';
      event.action = body.action;
      event.repository = body.repository.full_name;
    } else if (body.release) {
      // Release event
      event.type = 'release';
      event.action = body.action;
      event.repository = body.repository.full_name;
    }

    return event;
  }

  /**
   * Determine if event should trigger scan
   * @param {object} event - Parsed event
   * @returns {object} scan trigger config
   */
  shouldTriggerScan(event) {
    const trigger = {
      shouldScan: false,
      reason: 'No scan trigger',
      scanConfig: null,
    };

    switch (event.type) {
      case 'push': {
        // Scan on push to main/master/develop (not all branches to save quota)
        const mainBranches = ['main', 'master', 'develop', 'development'];
        if (mainBranches.includes(event.branch)) {
          trigger.shouldScan = true;
          trigger.reason = `Push to ${event.branch}`;
          trigger.scanConfig = {
            type: 'push',
            repository: event.repository,
            branch: event.branch,
            commits: event.commits,
            pusher: event.pusher,
            // Will scan new commits
            filesToScan: event.commits.flatMap((c) => [
              ...Object.keys(c.added || []),
              ...Object.keys(c.modified || []),
            ]),
          };
        } else {
          trigger.reason = `Skipping scan on feature branch: ${event.branch}`;
        }
        break;
      }

      case 'pull_request': {
        // Scan on PR open / sync (new commits)
        if (['opened', 'synchronize'].includes(event.action)) {
          trigger.shouldScan = true;
          trigger.reason = `Pull request ${event.action}`;
          trigger.scanConfig = {
            type: 'pull_request',
            repository: event.repository,
            prNumber: event.pullRequest.number,
            branch: event.pullRequest.branch,
            baseBranch: event.pullRequest.baseBranch,
            author: event.pullRequest.author,
            // Will compare against base branch
          };
        } else {
          trigger.reason = `Skipping scan on PR ${event.action}`;
        }
        break;
      }

      case 'release': {
        // Scan on release
        if (event.action === 'published') {
          trigger.shouldScan = true;
          trigger.reason = 'Release published';
          trigger.scanConfig = {
            type: 'release',
            repository: event.repository,
          };
        }
        break;
      }

      default:
        trigger.reason = `No scan trigger for ${event.type} event`;
    }

    return trigger;
  }

  /**
   * Generate scan comment for GitHub PR
   * @param {object} scanResults - Scan findings
   * @returns {string} markdown comment
   */
  generatePRComment(scanResults) {
    const { critical, high, medium, low, info, findings } = scanResults;
    const total = (critical || 0) + (high || 0) + (medium || 0) + (low || 0) + (info || 0);

    if (total === 0) {
      return `## ✅ SecureCode Scan Result
No security issues detected in this PR. Excellent work! 🎉`;
    }

    let comment = `## 🔍 SecureCode Scan Result\n\n`;

    if (critical > 0 || high > 0) {
      comment += `### ⚠️ Critical Issues Found\n`;
      comment += `- **Critical**: ${critical || 0}\n`;
      comment += `- **High**: ${high || 0}\n\n`;
      comment += `**Action Required**: Please review and fix these security issues before merging.\n\n`;
    }

    comment += `### Summary\n`;
    comment += `| Severity | Count |\n`;
    comment += `|----------|-------|\n`;
    comment += `| Critical | ${critical || 0} |\n`;
    comment += `| High | ${high || 0} |\n`;
    comment += `| Medium | ${medium || 0} |\n`;
    comment += `| Low | ${low || 0} |\n`;
    comment += `| Info | ${info || 0} |\n`;
    comment += `| **Total** | **${total}** |\n\n`;

    if (findings && findings.length > 0) {
      comment += `### Top Issues\n`;
      const topFindings = findings.slice(0, 5);
      for (const finding of topFindings) {
        comment += `- **${finding.severity}**: ${finding.title || 'Unnamed issue'} in \`${finding.fileName || 'unknown'}\`\n`;
        if (finding.explanation) {
          comment += `  > ${finding.explanation.substring(0, 100)}...\n`;
        }
      }
    }

    comment += `\n[View full scan results →](https://localhost:3000) *(Configure SecureCode dashboard URL)*`;

    return comment;
  }

  /**
   * Check PR merge safety
   * @param {object} scanResults
   * @returns {object} merge check result
   */
  checkMergeSafety(scanResults) {
    const critical = scanResults.critical || 0;
    const high = scanResults.high || 0;

    return {
      canMerge: critical === 0 && high < 3, // Adjust thresholds as needed
      blockReason: critical > 0 
        ? `Blocking merge: ${critical} critical issue(s) found`
        : high >= 3
        ? `Blocking merge: ${high} high severity issues found (threshold: 2)`
        : null,
      requiresReview: high > 0,
      autoFix: {
        available: true,
        message: 'Create auto-fix PR with security patches',
      },
    };
  }
}

module.exports = { GitHubWebhookHandler };
