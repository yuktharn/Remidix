// db.js - Universal Database Engine (PostgreSQL Primary with MySQL Support)
require("dotenv").config();
const { Pool: PgPool } = require("pg");
const mysql = require("mysql2/promise");

let dbType = process.env.DB_TYPE || "postgres"; // 'postgres' or 'mysql'
let activePool = null;

// Determine DB configuration
const isPostgresConfigured = Boolean(
  process.env.DATABASE_URL?.includes("postgres") ||
  process.env.PGHOST ||
  process.env.PGPORT ||
  process.env.DB_TYPE === "postgres" ||
  process.env.DB_PORT == 5432
);

// PostgreSQL Pool Initialization
function createPgPool() {
  const connectionString = process.env.DATABASE_URL;
  if (connectionString && connectionString.startsWith("postgres")) {
    return new PgPool({ connectionString });
  }

  return new PgPool({
    host: process.env.PGHOST || process.env.DB_HOST || "127.0.0.1",
    port: parseInt(process.env.PGPORT || process.env.DB_PORT || "5432", 10),
    user: process.env.PGUSER || "postgres",
    password: process.env.PGPASSWORD || process.env.DB_PASSWORD || "postgres",
    database: process.env.PGDATABASE || process.env.DB_NAME || "securecode",
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
  });
}

// MySQL Pool Initialization (Fallback/Alternative)
function createMySqlPool() {
  return mysql.createPool({
    host: process.env.DB_HOST || "127.0.0.1",
    port: parseInt(process.env.DB_PORT || "3306", 10),
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "sql1312",
    database: process.env.DB_NAME || "securecode",
    waitForConnections: true,
    connectionLimit: 15,
    queueLimit: 0,
  });
}

// Convert '?' placeholders to '$1', '$2' for PostgreSQL
function formatPgQuery(sql, params = []) {
  let paramIdx = 1;
  let formattedSql = sql.replace(/\?/g, () => `$${paramIdx++}`);

  // Handle MySQL specific function syntax differences if needed
  formattedSql = formattedSql.replace(/CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP/gi, "CURRENT_TIMESTAMP");

  return { sql: formattedSql, params };
}

// Wrapper for unified pool query execution
const dbWrapper = {
  dbType: "postgres",
  rawPool: null,

  async query(sql, params = []) {
    if (this.dbType === "postgres") {
      let { sql: pgSql, params: pgParams } = formatPgQuery(sql, params);
      const isInsert = /^\s*INSERT\s+INTO/i.test(pgSql);
      const hasReturning = /RETURNING/i.test(pgSql);

      if (isInsert && !hasReturning) {
        pgSql += " RETURNING id";
      }

      try {
        const res = await this.rawPool.query(pgSql, pgParams);
        if (isInsert) {
          const insertId = res.rows.length > 0 ? res.rows[0].id : null;
          return [{ insertId, affectedRows: res.rowCount, rows: res.rows }, res.fields];
        }
        if (/^\s*(UPDATE|DELETE)/i.test(pgSql)) {
          return [{ affectedRows: res.rowCount, rows: res.rows }, res.fields];
        }
        return [res.rows, res.fields];
      } catch (err) {
        // Fallback for tables without id column
        if (isInsert && err.message.includes('column "id" does not exist')) {
          const rawSqlWithoutReturning = pgSql.replace(/\s+RETURNING\s+id/i, "");
          const retryRes = await this.rawPool.query(rawSqlWithoutReturning, pgParams);
          return [{ insertId: null, affectedRows: retryRes.rowCount, rows: retryRes.rows }, retryRes.fields];
        }
        throw err;
      }
    } else {
      // MySQL execution
      return await this.rawPool.query(sql, params);
    }
  },

  async getConnection() {
    if (this.dbType === "postgres") {
      const client = await this.rawPool.connect();
      return {
        query: async (sql, params) => {
          let { sql: pgSql, params: pgParams } = formatPgQuery(sql, params);
          const isInsert = /^\s*INSERT\s+INTO/i.test(pgSql);
          if (isInsert && !/RETURNING/i.test(pgSql)) pgSql += " RETURNING id";
          const res = await client.query(pgSql, pgParams);
          if (isInsert) return [{ insertId: res.rows[0]?.id, affectedRows: res.rowCount }];
          return [res.rows, res.fields];
        },
        release: () => client.release(),
      };
    } else {
      return await this.rawPool.getConnection();
    }
  },
};

// PostgreSQL Schema Migrations
async function ensurePgSchema(pgPool) {
  const client = await pgPool.connect();
  try {
    console.log("Connected to PostgreSQL (SecureCode database)");

    // 1. Users
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        github_id INT UNIQUE,
        email VARCHAR(255),
        username VARCHAR(255) UNIQUE,
        avatar_url VARCHAR(512),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 2. GitHub Tokens
    await client.query(`
      CREATE TABLE IF NOT EXISTS github_tokens (
        id SERIAL PRIMARY KEY,
        user_id INT UNIQUE NOT NULL,
        encrypted_token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      );
    `);

    // 3. Projects
    await client.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        user_id INT,
        name VARCHAR(255) NOT NULL,
        platform VARCHAR(50) DEFAULT 'GitHub',
        repos_json JSONB DEFAULT '[]'::jsonb,
        github_owner VARCHAR(255),
        github_repo VARCHAR(255),
        github_url VARCHAR(512),
        encrypted_token TEXT,
        token_iv VARCHAR(255),
        token_auth_tag VARCHAR(255),
        security_score INT DEFAULT 0,
        risk_level VARCHAR(50),
        total_issues INT DEFAULT 0,
        critical_count INT DEFAULT 0,
        high_count INT DEFAULT 0,
        medium_count INT DEFAULT 0,
        low_count INT DEFAULT 0,
        info_count INT DEFAULT 0,
        last_scan TIMESTAMP,
        auto_scan_enabled BOOLEAN DEFAULT TRUE,
        auto_scan_frequency VARCHAR(50) DEFAULT 'daily',
        remediation_progress INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 4. Project Scans
    await client.query(`
      CREATE TABLE IF NOT EXISTS project_scans (
        id SERIAL PRIMARY KEY,
        project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        status VARCHAR(50) DEFAULT 'in_progress',
        risk_score INT DEFAULT 0,
        security_score INT DEFAULT 100,
        risk_level VARCHAR(50) DEFAULT 'Low',
        findings_json JSONB DEFAULT '[]'::jsonb,
        file_tree_json JSONB DEFAULT '[]'::jsonb,
        files_original_json JSONB DEFAULT '{}'::jsonb,
        files_corrected_json JSONB DEFAULT '{}'::jsonb,
        findings_by_file_json JSONB DEFAULT '{}'::jsonb,
        error_message TEXT,
        critical_count INT DEFAULT 0,
        high_count INT DEFAULT 0,
        medium_count INT DEFAULT 0,
        low_count INT DEFAULT 0,
        info_count INT DEFAULT 0,
        total_findings INT DEFAULT 0,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 5. Scan History (Standard & Snippet Scans)
    await client.query(`
      CREATE TABLE IF NOT EXISTS scan_history (
        id SERIAL PRIMARY KEY,
        project_id INT,
        scan_uid VARCHAR(100),
        source_code TEXT,
        file_name VARCHAR(255) DEFAULT 'snippet',
        language VARCHAR(50) DEFAULT 'javascript',
        total_lines INT DEFAULT 0,
        total_findings INT DEFAULT 0,
        critical_count INT DEFAULT 0,
        high_count INT DEFAULT 0,
        medium_count INT DEFAULT 0,
        low_count INT DEFAULT 0,
        info_count INT DEFAULT 0,
        findings_json JSONB DEFAULT '[]'::jsonb,
        full_corrected_code TEXT,
        risk_score INT DEFAULT 0,
        security_score INT DEFAULT 100,
        risk_level VARCHAR(50) DEFAULT 'Low',
        scan_mode VARCHAR(50) DEFAULT 'Standard',
        scan_status VARCHAR(50) DEFAULT 'completed',
        folder_name VARCHAR(255),
        file_tree_json JSONB DEFAULT '[]'::jsonb,
        files_original_json JSONB DEFAULT '{}'::jsonb,
        files_corrected_json JSONB DEFAULT '{}'::jsonb,
        findings_by_file_json JSONB DEFAULT '{}'::jsonb,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 6. Project PRs
    await client.query(`
      CREATE TABLE IF NOT EXISTS project_prs (
        id SERIAL PRIMARY KEY,
        project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        title VARCHAR(255) NOT NULL,
        status VARCHAR(50) DEFAULT 'open',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        merged_at TIMESTAMP NULL
      );
    `);

    // 7. Pull Requests
    await client.query(`
      CREATE TABLE IF NOT EXISTS pull_requests (
        id SERIAL PRIMARY KEY,
        project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        scan_id INT NULL,
        pr_number INT,
        pr_url VARCHAR(512),
        title VARCHAR(255),
        status VARCHAR(50) DEFAULT 'open',
        branch_name VARCHAR(255),
        fixes_json JSONB DEFAULT '[]'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        merged_at TIMESTAMP NULL
      );
    `);

    // 8. Deployments
    await client.query(`
      CREATE TABLE IF NOT EXISTS deployments (
        id SERIAL PRIMARY KEY,
        project_id INT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
        platform VARCHAR(50) DEFAULT 'render',
        service_type VARCHAR(50) DEFAULT 'backend',
        deployment_url VARCHAR(512),
        status VARCHAR(50) DEFAULT 'pending',
        logs_json JSONB DEFAULT '{}'::jsonb,
        environment_vars JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 9. Deployment Tokens
    await client.query(`
      CREATE TABLE IF NOT EXISTS deployment_tokens (
        id SERIAL PRIMARY KEY,
        user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        platform VARCHAR(50) NOT NULL,
        encrypted_token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 10. Copilot Chats
    await client.query(`
      CREATE TABLE IF NOT EXISTS copilot_chats (
        id SERIAL PRIMARY KEY,
        project_id INT NULL,
        user_id INT NULL,
        session_id VARCHAR(100),
        messages_json JSONB DEFAULT '[]'::jsonb,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("✓ PostgreSQL Database schema & tables verified successfully.");
  } finally {
    client.release();
  }
}

// Initialize Database Layer
async function initDatabase() {
  if (isPostgresConfigured) {
    try {
      const pgPool = createPgPool();
      await ensurePgSchema(pgPool);
      dbWrapper.dbType = "postgres";
      dbWrapper.rawPool = pgPool;
      console.log("✓ Primary Database: PostgreSQL Active");
      return;
    } catch (pgErr) {
      console.warn("PostgreSQL initialization note:", pgErr.message);
      console.log("Switching to MySQL connection...");
    }
  }

  // MySQL Fallback/Primary
  try {
    const myPool = createMySqlPool();
    const conn = await myPool.getConnection();
    console.log("Connected to MySQL (SecureCode database)");
    conn.release();
    dbWrapper.dbType = "mysql";
    dbWrapper.rawPool = myPool;
  } catch (myErr) {
    console.error("Database connection failed:", myErr.message);
  }
}

initDatabase();

module.exports = dbWrapper;
