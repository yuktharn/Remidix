// db.js - PostgreSQL connection setup
// Changed from MySQL to PostgreSQL

const { Pool } = require("pg");

const pool = new Pool({
  host: process.env.DB_HOST || "localhost",
  port: process.env.DB_PORT || 5432,
  user: process.env.DB_USER || "postgres",
  password: process.env.DB_PASSWORD || "password",
  database: process.env.DB_NAME || "securecode",
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

pool.on("error", (err) => {
  console.error("Unexpected error on idle client", err);
});

// Initialize database (run migrations)
async function initDatabase() {
  try {
    console.log("✓ PostgreSQL Connected");

    // Check if users table exists, if not run migrations
    const checkTable = await pool.query(
      `SELECT EXISTS (
        SELECT 1 FROM information_schema.tables 
        WHERE table_name = 'users'
      );`
    );

    if (!checkTable.rows[0].exists) {
      console.log("📦 Running database migrations...");
      const fs = require("fs");
      const schema = fs.readFileSync(__dirname + "/schema.sql", "utf8");
      const statements = schema.split(";").filter((s) => s.trim());

      for (const statement of statements) {
        if (statement.trim()) {
          await pool.query(statement);
        }
      }
      console.log("✓ Database migrations completed");
    } else {
      console.log("✓ Database tables already exist");
    }
  } catch (err) {
    console.error("Database initialization error:", err);
    process.exit(1);
  }
}

module.exports = pool;
module.exports.initDatabase = initDatabase;
