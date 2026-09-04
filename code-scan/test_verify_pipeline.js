// const http = require('http');

// const complexVulnerableCode = `const express = require('express');
// const mysql = require('mysql2');
// const { exec } = require('child_process');
// const crypto = require('crypto');
// const fs = require('fs');
// const https = require('https');

// const app = express();
// app.use(express.json());

// // 1. Hardcoded AWS API Secret
// const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
// const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

// // 2. SQL Injection
// app.get('/user', (req, res) => {
//   const userId = req.query.id;
//   const sql = "SELECT * FROM users WHERE id = '" + userId + "'";
//   db.query(sql, (err, result) => {
//     res.send(result);
//   });
// });

// // 3. Cross-Site Scripting (XSS)
// app.get('/welcome', (req, res) => {
//   const name = req.query.name;
//   res.send('<h1>Welcome ' + name + '</h1>');
// });

// // 4. Command Injection
// app.post('/ping', (req, res) => {
//   const host = req.body.host;
//   exec("ping -c 1 " + host, (err, stdout) => {
//     res.send(stdout);
//   });
// });

// // 5. Dangerous Code Evaluation (eval)
// app.post('/calc', (req, res) => {
//   const expr = req.body.formula;
//   const result = eval(expr);
//   res.json({ result });
// });

// // 6. Path Traversal
// app.get('/read', (req, res) => {
//   const file = req.query.filename;
//   fs.readFile('/var/data/' + file, 'utf8', (err, data) => {
//     res.send(data);
//   });
// });

// // 7. Weak Password Hashing (MD5)
// app.post('/login', (req, res) => {
//   const { username, password } = req.body;
//   const hash = crypto.createHash('md5').update(password).digest('hex');

//   // 8. Hardcoded Admin Authentication
//   if (username === 'admin' && password === 'admin123') {
//     return res.json({ role: 'superadmin', token: 'master-token-123' });
//   }

//   res.json({ hash });
// });

// // 9. Insecure TLS / Certificate validation disabled
// const agent = new https.Agent({
//   rejectUnauthorized: false
// });
// `;

// function sendRequest(options, postData) {
//   return new Promise((resolve, reject) => {
//     const req = http.request(options, (res) => {
//       let data = '';
//       res.on('data', (chunk) => { data += chunk; });
//       res.on('end', () => {
//         try {
//           resolve({ status: res.statusCode, data: JSON.parse(data) });
//         } catch (e) {
//           resolve({ status: res.statusCode, text: data });
//         }
//       });
//     });
//     req.on('error', reject);
//     if (postData) req.write(postData);
//     req.end();
//   });
// }

// async function testFullPipeline() {
//   console.log('=== 1. SUBMITTING MULTI-VULNERABILITY CODE TO POST /scan ===');
//   const postPayload = JSON.stringify({
//     code: complexVulnerableCode,
//     fileName: 'server.js',
//     scanMode: 'Deep Scan',
//     entropyEnabled: true
//   });

//   const scanRes = await sendRequest({
//     hostname: 'localhost',
//     port: 4000,
//     path: '/scan',
//     method: 'POST',
//     headers: {
//       'Content-Type': 'application/json',
//       'Content-Length': Buffer.byteLength(postPayload)
//     }
//   }, postPayload);

//   console.log('POST /scan HTTP Status:', scanRes.status);
//   const scanData = scanRes.data;
//   console.log('Scan ID:', scanData.id);
//   console.log('Scan UID:', scanData.scanUid);
//   console.log('Security Score:', scanData.securityScore, '/ 100');
//   console.log('Risk Score:', scanData.riskScore);
//   console.log('Risk Level:', scanData.riskLevel);
//   console.log('Total Findings Detected:', scanData.totalFindings);
//   console.log('Severity Breakdown:', {
//     critical: scanData.criticalCount,
//     high: scanData.highCount,
//     medium: scanData.mediumCount,
//     low: scanData.lowCount,
//     info: scanData.infoCount
//   });

//   console.log('\n=== 2. DETECTED VULNERABILITY DETAILS ===');
//   scanData.findings.forEach((f, idx) => {
//     console.log(`[#${idx + 1}] [${f.severity.toUpperCase()}] ${f.type} | Line ${f.line}`);
//     console.log(`     Category:    ${f.category}`);
//     console.log(`     CWE / OWASP: ${f.cwe || 'N/A'} | ${f.owasp || 'N/A'}`);
//     console.log(`     Problem:     ${f.problem || f.explanation}`);
//     console.log(`     Why Risky:   ${f.whyRisky || f.impact}`);
//     console.log(`     How to Fix:  ${f.howToFix || f.fix}`);
//     console.log(`     Flagged:     ${JSON.stringify((f.vulnerableCode || '').trim().slice(0, 70))}`);
//     console.log(`     Correction:  ${JSON.stringify((f.correctedCode || '').trim().slice(0, 70))}`);
//     console.log('');
//   });

//   console.log('=== 3. VERIFYING DATABASE RETRIEVAL VIA GET /scan/' + scanData.id + ' ===');
//   const getRes = await sendRequest({
//     hostname: 'localhost',
//     port: 4000,
//     path: '/scan/' + scanData.id,
//     method: 'GET'
//   });

//   console.log('GET /scan/:id Status:', getRes.status);
//   const dbData = getRes.data;
//   console.log('DB Scan UID:', dbData.scanUid);
//   console.log('DB Findings Count:', dbData.findings.length);
//   console.log('DB Security Score:', dbData.securityScore);
//   console.log('DB Full Corrected Code Available:', Boolean(dbData.fullCorrectedCode));

//   console.log('\n=== 4. VERIFYING GET /history ===');
//   const histRes = await sendRequest({
//     hostname: 'localhost',
//     port: 4000,
//     path: '/history',
//     method: 'GET'
//   });
//   console.log('Total history records:', histRes.data.history.length);
//   console.log('Latest history item matches scan UID:', histRes.data.history[0]?.scanUid === scanData.scanUid);
// }

// testFullPipeline().catch(console.error);
