// Long-running test for /ai/generate-fix with generous timeout
const ctrl = new AbortController();
const t = setTimeout(() => ctrl.abort(), 300000); // 5 min

console.log('Testing /ai/generate-fix with Ollama (may take a while for cold model)...');
const start = Date.now();

fetch('https://remidix-backend.onrender.com/ai/generate-fix', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  signal: ctrl.signal,
  body: JSON.stringify({
    code: 'const q = "SELECT * FROM users WHERE id = " + req.query.id;',
    vulnerability_type: 'SQL Injection',
    language: 'JavaScript',
    file_name: 'server.js'
  })
}).then(r => {
  clearTimeout(t);
  const elapsed = ((Date.now() - start) / 1000).toFixed(1);
  console.log(`Completed in ${elapsed}s, status ${r.status}`);
  return r.json();
}).then(d => {
  console.log(JSON.stringify(d, null, 2));
}).catch(e => {
  clearTimeout(t);
  console.error('Error:', e.message);
});
