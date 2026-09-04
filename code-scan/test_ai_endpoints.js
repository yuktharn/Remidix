const BASE = 'https://remidix-backend.onrender.com';

async function test() {
  console.log('=== AI ENGINE ENDPOINT TESTS ===\n');

  // 1. Health
  const h = await fetch(`${BASE}/ai/health`).then(r => r.json());
  console.log('[1] GET /ai/health:', JSON.stringify(h));

  // 2. detect-secrets with real secrets
  const ds = await fetch(`${BASE}/ai/detect-secrets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      code: 'const key = "AKIA1234567890ABCDEF";\nconst ghp = "ghp_abc123def456ghi789jkl012mno345pqr678";'
    })
  }).then(r => r.json());
  console.log(`[2] POST /ai/detect-secrets: ${ds.secrets.length} secrets found, has_secrets=${ds.has_secrets}`);
  ds.secrets.forEach(s => console.log(`    - ${s.type} at line ${s.line}: ${s.match}`));

  // 3. detect-secrets with no code
  const ds400 = await fetch(`${BASE}/ai/detect-secrets`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  console.log(`[3] POST /ai/detect-secrets (no code): status ${ds400.status} ${ds400.status === 400 ? 'PASS' : 'FAIL'}`);

  // 4. explain with no code
  const ex400 = await fetch(`${BASE}/ai/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  console.log(`[4] POST /ai/explain (no code): status ${ex400.status} ${ex400.status === 400 ? 'PASS' : 'FAIL'}`);

  // 5. generate-fix with no code
  const gf400 = await fetch(`${BASE}/ai/generate-fix`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({})
  });
  console.log(`[5] POST /ai/generate-fix (no code): status ${gf400.status} ${gf400.status === 400 ? 'PASS' : 'FAIL'}`);

  // 6. explain with Ollama (if running)
  console.log('\n[6] Testing /ai/explain with Ollama (may fail if Ollama not running)...');
  try {
    const ex = await fetch(`${BASE}/ai/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: 'const query = "SELECT * FROM users WHERE id = " + req.query.id;',
        vulnerability_type: 'SQL Injection',
        language: 'JavaScript',
        file_name: 'server.js'
      })
    });
    const exData = await ex.json();
    console.log(`    Status: ${ex.status}`);
    if (ex.ok) {
      console.log(`    severity: ${exData.severity}`);
      console.log(`    explanation: ${(exData.explanation || '').slice(0, 120)}...`);
      console.log(`    -> PASS`);
    } else {
      console.log(`    Error: ${exData.error || 'unknown'}`);
      console.log(`    -> Ollama not running (expected if no local LLM)`);
    }
  } catch (e) {
    console.log(`    -> Ollama not reachable: ${e.message}`);
  }

  // 7. generate-fix with Ollama (if running)
  console.log('\n[7] Testing /ai/generate-fix with Ollama (may fail if Ollama not running)...');
  try {
    const gf = await fetch(`${BASE}/ai/generate-fix`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        code: 'const query = "SELECT * FROM users WHERE id = " + req.query.id;',
        vulnerability_type: 'SQL Injection',
        language: 'JavaScript',
        file_name: 'server.js'
      })
    });
    const gfData = await gf.json();
    console.log(`    Status: ${gf.status}`);
    if (gf.ok) {
      console.log(`    confidence: ${gfData.confidence}`);
      console.log(`    fixed_code: ${(gfData.fixed_code || '').slice(0, 120)}...`);
      console.log(`    -> PASS`);
    } else {
      console.log(`    Error: ${gfData.error || 'unknown'}`);
      console.log(`    -> Ollama not running (expected if no local LLM)`);
    }
  } catch (e) {
    console.log(`    -> Ollama not reachable: ${e.message}`);
  }

  console.log('\n=== ALL AI ENDPOINT TESTS COMPLETE ===');
}

test().catch(e => console.error('FATAL:', e));
