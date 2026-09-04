const { Client } = require('pg');

async function test(pw) {
  const c = new Client({ host: '127.0.0.1', port: 5432, user: 'postgres', password: pw, database: 'postgres' });
  try {
    await c.connect();
    console.log('SUCCESS with PostgreSQL password:', pw);
    const checkDb = await c.query("SELECT 1 FROM pg_database WHERE datname = 'securecode'");
    if (checkDb.rows.length === 0) {
      await c.query("CREATE DATABASE securecode");
      console.log('Created database securecode in PostgreSQL');
    } else {
      console.log('Database securecode exists in PostgreSQL');
    }
    await c.end();
    return pw;
  } catch (e) {
    return null;
  }
}

async function run() {
  for (const pw of ['sql1312', 'postgres', 'password', 'root', 'admin', '123456', '']) {
    const matched = await test(pw);
    if (matched !== null) {
      console.log('PostgreSQL Ready with password:', matched);
      process.exit(0);
    }
  }
  console.log('No default postgres password matched');
}

run();
