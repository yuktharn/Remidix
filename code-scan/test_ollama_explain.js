const ctrl = new AbortController();
const t = setTimeout(() => ctrl.abort(), 120000);

fetch('https://remidix-backend.onrender.com/ai/explain', {
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
  return r.json();
}).then(d => {
  console.log(JSON.stringify(d, null, 2));
}).catch(e => {
  clearTimeout(t);
  console.error(e.message);
});
