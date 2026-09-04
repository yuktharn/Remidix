const http = require('http');
const code = `const express = require("express");
const mysql = require("mysql2");
const { exec } = require("child_process");

const app = express();

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password123",
  database: "users"
});

app.get("/user", (req, res) => {
  const username = req.query.username;
  const query = \`SELECT * FROM users WHERE username = '\${username}'\`;

  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(\`ping -c 1 \${host}\`, (err, stdout) => {
    if (err) return res.status(500).send(err.message);
    res.send(stdout);
  });
});

const API_KEY = "sk_test_1234567890abcdef";

app.listen(4000);`;

const body = JSON.stringify({
  code,
  entropyEnabled: true,
  checks: {
    secrets: true,
    vuln: true,
    deps: true,
    aiContext: true,
    riskPrioritization: true,
    confidence: true
  }
});

const req = http.request({
  hostname: 'localhost',
  port: 4000,
  path: '/scan',
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) }
}, res => {
  let d = '';
  res.on('data', c => d += c);
  res.on('end', () => {
    console.log('Status:', res.statusCode);
    try {
      const j = JSON.parse(d);
      console.log('Findings:', j.findings?.length);
      console.log('Total:', j.totalFindings);
      console.log('Critical:', j.critical);
      console.log('High:', j.high);
      console.log('Keys:', Object.keys(j).join(', '));
      if (j.findings?.length > 0) {
        console.log('First finding:', JSON.stringify(j.findings[0], null, 2).slice(0, 300));
      }
    } catch (e) {
      console.log('Parse error:', e.message);
      console.log('Response:', d.slice(0, 500));
    }
  });
});
req.write(body);
req.end();
