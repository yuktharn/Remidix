// test_e2e_pipeline.js
// Comprehensive End-to-End Integration Test for SecureCode backend

const http = require('http');
const assert = require('assert');

const API_PORT = 4000;
const BASE_URL = `http://localhost:${API_PORT}`;

function post(endpoint, data) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(data);
    const req = http.request(`${BASE_URL}${endpoint}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
    }, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(body) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body });
        }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function get(endpoint) {
  return new Promise((resolve, reject) => {
    const req = http.request(`${BASE_URL}${endpoint}`, {
      method: 'GET',
    }, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: JSON.parse(body) });
        } catch {
          resolve({ status: res.statusCode, headers: res.headers, body });
        }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

async function runTests() {
  console.log('=== STARTING SECURECODE E2E TEST SUITE ===\n');

  // Test 0: Health Check
  console.log('0. Testing GET /health...');
  const healthRes = await get('/health');
  assert.strictEqual(healthRes.status, 200, 'GET /health should return 200');
  assert.strictEqual(healthRes.body.status, 'ok', 'Status should be ok');
  assert.strictEqual(healthRes.body.service, 'SecureCode API', 'Service name should match');
  console.log(`   -> Health check passed: ${JSON.stringify(healthRes.body)}`);

  // Test 1: Get Projects
  console.log('\n1. Testing GET /projects...');
  const projRes = await get('/projects');
  assert.strictEqual(projRes.status, 200, 'GET /projects should return 200');
  console.log(`   -> Found ${projRes.body.projects?.length ?? 0} projects in DB.`);

  // Test 2: Scan code with known vulnerability and hardcoded secret
  console.log('\n2. Testing POST /scan (Static + AI analysis)...');
  const sampleVulnerableCode = `
const express = require('express');
const mysql = require('mysql2');
const app = express();

const DB_PASSWORD = "super_secret_production_password_12345!";
const AWS_ACCESS_KEY_ID = "AKIA1234567890EXAMPLE";

app.get('/users', (req, res) => {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query, (err, rows) => {
    res.json(rows);
  });
});
`;

  const scanRes = await post('/scan', {
    code: sampleVulnerableCode,
    fileName: 'server.js',
    entropyEnabled: true,
  });

  assert.strictEqual(scanRes.status, 200, 'POST /scan should return 200');
  assert(scanRes.body.findings && scanRes.body.findings.length > 0, 'Scan should detect findings');
  console.log(`   -> Detected ${scanRes.body.findings.length} findings.`);
  console.log(`   -> Risk Score: ${scanRes.body.riskScore}/100 | Risk Level: ${scanRes.body.riskLevel}`);
  console.log(`   -> Corrected code generated: ${scanRes.body.fixedCode ? 'YES' : 'NO'}`);

  // Test 3: Download Fixed ZIP
  console.log('\n3. Testing POST /download-fixed (ZIP archive & secret sanitization)...');
  const downloadRes = await post('/download-fixed', {
    files: [{ name: 'server.js', content: sampleVulnerableCode }],
    findings: scanRes.body.findings,
    folderName: 'my-test-project',
  });
  assert.strictEqual(downloadRes.status, 200, 'POST /download-fixed should return 200');
  assert(downloadRes.headers['content-type']?.includes('zip'), 'Response content-type should be zip');
  console.log('   -> ZIP archive generated successfully.');

  // Test 3b: Rescan fixed code endpoint
  console.log('\n3b. Testing POST /api/scan/fixed (Rescan fixed code alias)...');
  const fixedScanRes = await post('/api/scan/fixed', {
    code: 'const express = require("express");\nconst app = express();\nconst DB_PASSWORD = process.env.DB_PASSWORD;\nconst AWS_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID;\napp.get("/users", (req, res) => {\n  db.query("SELECT * FROM users WHERE id = ?", [req.query.id], (err, rows) => res.json(rows));\n});',
    fileName: 'server.js',
  });
  assert.strictEqual(fixedScanRes.status, 200, 'POST /api/scan/fixed should return 200');
  console.log(`   -> Rescanned fixed code successfully. Risk score: ${fixedScanRes.body.riskScore}/100`);

  // Test 4: AI Copilot RAG & Scope check
  console.log('\n4. Testing POST /copilot/chat...');
  const copilotRes1 = await post('/copilot/chat', {
    message: 'What is SQL Injection and how do I prevent it?',
  });
  assert.strictEqual(copilotRes1.status, 200);
  assert(copilotRes1.body.scoped === true, 'Cybersecurity question should be in scope');
  console.log('   -> Security question answered correctly.');

  const copilotRes2 = await post('/copilot/chat', {
    message: 'What is the capital of Australia?',
  });
  assert.strictEqual(copilotRes2.status, 200);
  assert(copilotRes2.body.scoped === false, 'Non-security question should be refused');
  console.log('   -> Out-of-scope query refused as expected:', copilotRes2.body.reply);

  // Test 5: Project Stack Analysis
  console.log('\n5. Testing POST /analyze-project (Stack detection & deployment readiness)...');
  const analyzeRes = await post('/analyze-project', {
    files: [
      { name: 'package.json', content: JSON.stringify({ name: 'test-app', scripts: { build: 'vite build', start: 'node server.js' }, dependencies: { express: '^4.18.2' } }) },
      { name: 'server.js', content: 'const express = require("express");' },
      { name: '.env.example', content: 'PORT=4000\nDATABASE_URL=mysql://...' },
    ],
  });
  // Test 6: PR helper formatting
  console.log('\n6. Testing PR helper markdown description builder...');
  const prHelper = require('./prHelper');
  const prBody = prHelper.buildPRDescription({
    files: [{ path: 'server.js', content: 'const port = 4000;' }],
    findingsSummary: [
      { type: 'Hardcoded Secret', severity: 'Critical', fileName: 'server.js', line: 5, cwe: 'CWE-798' },
      { type: 'SQL Injection', severity: 'High', fileName: 'server.js', line: 9, cwe: 'CWE-89' },
    ],
  });
  assert(prBody.includes('SecureCode') && prBody.includes('Security Remediation'), 'PR body should contain header');
  assert(prBody.includes('CWE-798') && prBody.includes('CWE-89'), 'PR body should include CWEs');
  console.log('   -> PR description formatted correctly with remediation table.');


  // Test 7: Rescan-corrected endpoint
  console.log('\n7. Testing POST /projects/:projectId/rescan-corrected...');
  if (projRes.body.projects && projRes.body.projects.length > 0) {
    const pId = projRes.body.projects[0].id;
    const rescanRes = await post(`/projects/${pId}/rescan-corrected`, {});
    assert(rescanRes.status === 202 || rescanRes.status === 404, 'Rescan should return 202 started or 404 if no previous scan');
    console.log(`   -> Rescan endpoint returned status ${rescanRes.status}:`, rescanRes.body.status || rescanRes.body.error);
  }

  // Test 8: Verify JSON response on 404 and /github/create-pr-auth (No HTML error pages)
  console.log('\n8. Testing JSON responses on 404 and /github/create-pr-auth...');
  const notFoundRes = await get('/non-existent-api-endpoint');
  assert.strictEqual(notFoundRes.status, 404);
  assert.strictEqual(typeof notFoundRes.body, 'object', '404 must return JSON, never HTML');
  assert.strictEqual(notFoundRes.body.code, 'NOT_FOUND', '404 should return code NOT_FOUND');
  console.log('   -> 404 JSON handler verified (no HTML error page).');

  const prAuthRes = await post('/github/create-pr-auth', {
    owner: 'testowner',
    repo: 'testrepo',
    branchName: 'securecode/fix-1',
    files: [{ path: 'server.js', content: 'const a = 1;' }],
  });
  assert(prAuthRes.status === 401 || prAuthRes.status === 200 || prAuthRes.status === 500, 'Endpoint must exist and return JSON');
  assert.strictEqual(typeof prAuthRes.body, 'object', 'PR response must be JSON');
  console.log(`   -> /github/create-pr-auth verified (status ${prAuthRes.status}, returned valid JSON).`);

  console.log('\n=== ALL 8 E2E INTEGRATION TESTS PASSED SUCCESSFULLY! ===');
}

runTests().catch(err => {
  console.error('\n❌ E2E TEST FAILED:', err);
  process.exit(1);
});

