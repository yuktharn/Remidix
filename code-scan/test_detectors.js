const { scanCode } = require('./detectors');

const testCode = `const express = require('express');
const mysql = require('mysql2');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const https = require('https');

const app = express();
app.use(express.json());

// 1. Hardcoded AWS API Secret
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// 2. SQL Injection
app.get('/user', (req, res) => {
  const userId = req.query.id;
  const sql = "SELECT * FROM users WHERE id = '" + userId + "'";
  db.query(sql, (err, result) => {
    res.send(result);
  });
});

// 3. Cross-Site Scripting (XSS)
app.get('/welcome', (req, res) => {
  const name = req.query.name;
  res.send('<h1>Welcome ' + name + '</h1>');
});

// 4. Command Injection
app.post('/ping', (req, res) => {
  const host = req.body.host;
  exec("ping -c 1 " + host, (err, stdout) => {
    res.send(stdout);
  });
});

// 5. Dangerous Code Evaluation (eval)
app.post('/calc', (req, res) => {
  const expr = req.body.formula;
  const result = eval(expr);
  res.json({ result });
});

// 6. Path Traversal
app.get('/read', (req, res) => {
  const file = req.query.filename;
  fs.readFile('/var/data/' + file, 'utf8', (err, data) => {
    res.send(data);
  });
});

// 7. Weak Password Hashing (MD5)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const hash = crypto.createHash('md5').update(password).digest('hex');

  // 8. Hardcoded Admin Authentication
  if (username === 'admin' && password === 'admin123') {
    return res.json({ role: 'superadmin', token: 'master-token-123' });
  }

  res.json({ hash });
});

// 9. Insecure TLS / Certificate validation disabled
const agent = new https.Agent({
  rejectUnauthorized: false
});
`;

const result = scanCode(testCode, { entropyEnabled: true });
console.log('=== STATIC DETECTOR RESULTS ===');
console.log('Total findings:', result.totalFindings);
console.log('Critical:', result.critical, '| High:', result.high, '| Medium:', result.medium, '| Low:', result.low, '| Info:', result.info);
console.log('');
result.findings.forEach((f, i) => {
  console.log(`[${i + 1}] [${f.severity.toUpperCase()}] ${f.type}`);
  console.log(`    Category: ${f.category}`);
  console.log(`    Line: ${f.line}`);
  console.log(`    CWE: ${f.cwe}`);
  console.log(`    OWASP: ${f.owasp}`);
  console.log(`    Method: ${f.method}`);
  console.log('');
});

console.log('Expected vulnerabilities:');
console.log('  1. Hardcoded AWS Access Key');
console.log('  2. Hardcoded AWS Secret Key');
console.log('  3. SQL Injection');
console.log('  4. XSS');
console.log('  5. Command Injection');
console.log('  6. Eval/Code Execution');
console.log('  7. Path Traversal');
console.log('  8. Weak Password Hashing (MD5)');
console.log('  9. Hardcoded Admin Credentials');
console.log('  10. Insecure TLS');
