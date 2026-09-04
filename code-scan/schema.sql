-- schema.sql
-- PostgreSQL Database Schema for SecureCode AI Platform

-- Users table (from GitHub OAuth)
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  github_id INT UNIQUE,
  email VARCHAR(255),
  username VARCHAR(255) UNIQUE,
  avatar_url VARCHAR(255),
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

-- GitHub OAuth tokens (encrypted)
CREATE TABLE IF NOT EXISTS github_tokens (
  id SERIAL PRIMARY KEY,
  user_id INT UNIQUE NOT NULL,
  encrypted_token TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Projects (repositories from GitHub)
CREATE TABLE IF NOT EXISTS projects (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL,
  name VARCHAR(255),
  platform VARCHAR(50), -- 'github', 'gitlab'
  repos_json JSONB DEFAULT '[]'::jsonb,
  github_owner VARCHAR(255),
  github_repo VARCHAR(255),
  github_url VARCHAR(255),
  encrypted_token TEXT,
  security_score INT DEFAULT 0,
  risk_level VARCHAR(50),
  total_issues INT DEFAULT 0,
  critical_count INT DEFAULT 0,
  high_count INT DEFAULT 0,
  medium_count INT DEFAULT 0,
  low_count INT DEFAULT 0,
  info_count INT DEFAULT 0,
  last_scan TIMESTAMP,
  auto_scan_enabled BOOLEAN DEFAULT FALSE,
  auto_scan_frequency VARCHAR(50),
  remediation_progress INT DEFAULT 0,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_id (user_id)
);

-- Scan history
CREATE TABLE IF NOT EXISTS scan_history (
  id SERIAL PRIMARY KEY,
  project_id INT,
  scan_uid VARCHAR(255) UNIQUE,
  github_repo VARCHAR(255),
  github_owner VARCHAR(255),
  github_branch VARCHAR(255),
  github_commit_sha VARCHAR(255),
  source_code LONGTEXT,
  file_name VARCHAR(255),
  language VARCHAR(50),
  total_lines INT,
  total_findings INT DEFAULT 0,
  critical_count INT DEFAULT 0,
  high_count INT DEFAULT 0,
  medium_count INT DEFAULT 0,
  low_count INT DEFAULT 0,
  info_count INT DEFAULT 0,
  risk_score INT DEFAULT 0,
  security_score INT DEFAULT 0,
  risk_level VARCHAR(50),
  findings_json JSONB DEFAULT '[]'::jsonb,
  file_tree_json JSONB DEFAULT '[]'::jsonb,
  findings_by_file_json JSONB DEFAULT '{}'::jsonb,
  full_corrected_code LONGTEXT,
  files_original_json JSONB DEFAULT '[]'::jsonb,
  files_corrected_json JSONB DEFAULT '[]'::jsonb,
  scan_status VARCHAR(50) DEFAULT 'completed',
  scan_mode VARCHAR(50) DEFAULT 'standard',
  scanned_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  INDEX idx_project_scan (project_id, scanned_at)
);

-- Pull requests created by copilot
CREATE TABLE IF NOT EXISTS pull_requests (
  id SERIAL PRIMARY KEY,
  project_id INT NOT NULL,
  scan_id INT,
  pr_number INT,
  pr_url VARCHAR(255),
  title VARCHAR(255),
  status VARCHAR(50), -- 'open', 'merged', 'closed'
  branch_name VARCHAR(255),
  fixes_json JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMP DEFAULT NOW(),
  merged_at TIMESTAMP,
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE SET NULL
);

-- Deployments (Vercel, Render, Railway)
CREATE TABLE IF NOT EXISTS deployments (
  id SERIAL PRIMARY KEY,
  project_id INT NOT NULL,
  platform VARCHAR(50), -- 'vercel', 'render', 'railway'
  service_type VARCHAR(50), -- 'frontend', 'backend', 'database'
  deployment_url VARCHAR(255),
  status VARCHAR(50), -- 'pending', 'deploying', 'live', 'failed'
  logs_json JSONB DEFAULT '{}'::jsonb,
  environment_vars JSONB DEFAULT '{}'::jsonb,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
);

-- Deployment platform OAuth tokens
CREATE TABLE IF NOT EXISTS deployment_tokens (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL,
  platform VARCHAR(50), -- 'vercel', 'render', 'railway'
  encrypted_token TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  UNIQUE (user_id, platform)
);

-- Webhook events
CREATE TABLE IF NOT EXISTS webhook_events (
  id SERIAL PRIMARY KEY,
  project_id INT NOT NULL,
  event_type VARCHAR(50), -- 'push', 'pull_request', 'workflow_run'
  github_payload JSONB DEFAULT '{}'::jsonb,
  scan_id INT,
  status VARCHAR(50) DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT NOW(),
  FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
  FOREIGN KEY (scan_id) REFERENCES scan_history(id) ON DELETE SET NULL
);

-- Create indices for performance
CREATE INDEX IF NOT EXISTS idx_users_github_id ON users(github_id);
CREATE INDEX IF NOT EXISTS idx_github_tokens_user_id ON github_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_user_id ON projects(user_id);
CREATE INDEX IF NOT EXISTS idx_projects_github ON projects(github_owner, github_repo);
CREATE INDEX IF NOT EXISTS idx_scan_history_project ON scan_history(project_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_timestamp ON scan_history(scanned_at);
CREATE INDEX IF NOT EXISTS idx_deployments_project ON deployments(project_id);
CREATE INDEX IF NOT EXISTS idx_webhook_events_project ON webhook_events(project_id);
