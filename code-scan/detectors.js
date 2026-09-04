// detectors.js
// High-precision static security detectors and pattern analyzers.
// Scans the ENTIRE file (not a single extracted line), detects vulnerabilities
// across 20 security categories, and returns multiple independent findings per
// file. Every finding carries the exact line(s), a per-finding vulnerable
// snippet and a distinct corrected (fixed) snippet, plus severity / CWE / OWASP
// / explanation / impact / remediation.
"use strict";

// Shannon entropy calculation for secret detection
function shannonEntropy(str) {
  const freq = {};
  for (const char of str) freq[char] = (freq[char] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const char in freq) {
    const p = freq[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function maskSecret(secret) {
  if (!secret) return "";
  if (secret.length <= 8) return "*".repeat(secret.length);
  return secret.slice(0, 4) + "*".repeat(Math.max(secret.length - 8, 4)) + secret.slice(-4);
}

// Extract context lines around a target line number
function extractCodeSnippet(lines, lineNum, context = 1) {
  const start = Math.max(0, lineNum - 1 - context);
  const end = Math.min(lines.length, lineNum + context);
  return lines.slice(start, end).join("\n");
}

// --------------------------------------------------------------------------
// Small code-parsing helpers shared by the fix builders.
// --------------------------------------------------------------------------

// Index of the ')' matching the '(' at openIdx (honours quotes/backticks).
function findMatchingParen(str, openIdx) {
  let depth = 0;
  let inStr = null;
  let escaped = false;
  for (let i = openIdx; i < str.length; i++) {
    const ch = str[i];
    if (inStr) {
      if (escaped) { escaped = false; continue; }
      if (ch === "\\") { escaped = true; continue; }
      if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { inStr = ch; continue; }
    if (ch === "(") depth++;
    else if (ch === ")") {
      depth--;
      if (depth === 0) return i;
    }
  }
  return -1;
}

// Split on top-level commas (outside strings, brackets, parens, braces).
function splitTopLevel(str) {
  const parts = [];
  let depth = 0;
  let cur = "";
  let inStr = null;
  let esc = false;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (inStr) {
      cur += ch;
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { inStr = ch; cur += ch; continue; }
    if (ch === "(" || ch === "[" || ch === "{") { depth++; cur += ch; continue; }
    if (ch === ")" || ch === "]" || ch === "}") { depth--; cur += ch; continue; }
    if (ch === "," && depth === 0) { parts.push(cur); cur = ""; continue; }
    cur += ch;
  }
  parts.push(cur);
  return parts;
}

// Parse a template-literal body into static literals + ${expr} params.
function tokenizeTemplate(body) {
  const literals = [];
  const params = [];
  let lit = "";
  let i = 0;
  while (i < body.length) {
    const start = body.indexOf("${", i);
    if (start < 0) { lit += body.slice(i); i = body.length; break; }
    lit += body.slice(i, start);
    let depth = 1;
    let j = start + 2;
    for (; j < body.length; j++) {
      if (body[j] === "{") depth++;
      else if (body[j] === "}") { depth--; if (depth === 0) break; }
    }
    const expr = body.slice(start + 2, j);
    literals.push(lit);
    lit = "";
    params.push(expr.trim());
    i = j + 1;
  }
  literals.push(lit);
  return { literals, params };
}

// Parse a '+'-concatenation expression (JS/PHP) into string pieces + params.
// Example:  "SELECT * FROM users WHERE id = '" + userId + "'"
// ->  [{s:'SELECT * FROM users WHERE id = '}, {x:'userId'}, {s:"'"}]
function tokenizeConcat(str) {
  const segs = [];
  const n = str.length;
  let i = 0;
  while (i < n) {
    const ch = str[i];
    if (ch === "'" || ch === '"' || ch === "`") {
      if (ch === "`") {
        let k = i + 1;
        let depth = -1;
        let tokEnd = -1;
        for (; k < n; k++) {
          const c = str[k];
          if (c === "\\") k++;
          else if (c === "`" && depth <= 0) { tokEnd = k; break; }
          else if (c === "{") depth = depth < 0 ? 1 : depth + 1;
          else if (c === "}") depth--;
        }
        const body = tokEnd === -1 ? str.slice(i + 1) : str.slice(i + 1, tokEnd);
        const t = tokenizeTemplate(body);
        for (let p = 0; p < t.params.length; p++) {
          if (t.literals[p]) segs.push({ s: t.literals[p] });
          segs.push({ x: t.params[p] });
        }
        segs.push({ s: t.literals[t.literals.length - 1] || "" });
        i = tokEnd === -1 ? n : tokEnd + 1;
        continue;
      }
      let k = i + 1;
      let esc = false;
      let lit = "";
      for (; k < n; k++) {
        const c = str[k];
        if (esc) { lit += c; esc = false; }
        else if (c === "\\") { esc = true; }
        else if (c === ch) break;
        else lit += c;
      }
      segs.push({ s: lit });
      i = Math.min(k + 1, n);
      continue;
    }
    let depth = 0;
    let inStrQ = null;
    let escQ = false;
    const start = i;
    let k = i;
    for (; k < n; k++) {
      const c = str[k];
      if (inStrQ) {
        if (escQ) escQ = false;
        else if (c === "\\") escQ = true;
        else if (c === inStrQ) inStrQ = null;
        continue;
      }
      if (c === "'" || c === '"' || c === "`") { inStrQ = c; continue; }
      if (c === "(" || c === "[" || c === "{") depth++;
      else if (c === ")" || c === "]" || c === "}") depth--;
      else if (c === "+" && depth === 0) break;
    }
    const token = str.slice(start, k).trim();
    if (token) segs.push({ x: token });
    i = k + 1;
  }
  const merged = [];
  for (const seg of segs) {
    if (seg.s !== undefined && merged.length && merged[merged.length - 1].s !== undefined) {
      merged[merged.length - 1].s += seg.s;
    } else {
      merged.push(seg.s !== undefined ? { s: seg.s } : { x: seg.x });
    }
  }
  return merged;
}

function hasSqlKeywords(sql) {
  return /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|CREATE|ALTER|DROP|JOIN)/i.test(sql);
}

function findTopLevelPercent(str) {
  let inStr = null;
  let esc = false;
  let depth = 0;
  for (let i = 0; i < str.length; i++) {
    const ch = str[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === inStr) inStr = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") { inStr = ch; continue; }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth--;
    else if (ch === "%" && !(str[i + 1] === "%")) return i;
  }
  return -1;
}

function splitFString(body) {
  const literals = [];
  const params = [];
  let lit = "";
  let i = 0;
  while (i < body.length) {
    if (body[i] === "{" && body[i + 1] === "{") { lit += "{"; i += 2; continue; }
    if (body[i] === "}" && body[i + 1] === "}") { lit += "}"; i += 2; continue; }
    if (body[i] === "{") {
      let depth = 1;
      let j = i + 1;
      for (; j < body.length; j++) {
        if (body[j] === "{") depth++;
        else if (body[j] === "}") { depth--; if (depth === 0) break; }
      }
      literals.push(lit);
      lit = "";
      params.push(body.slice(i + 1, j).trim());
      i = j + 1;
      continue;
    }
    lit += body[i];
    i++;
  }
  literals.push(lit);
  return { literals, params };
}

// --------------------------------------------------------------------------
// Fix builders: each one returns the fully corrected snippet text for the
// vulnerable line (or a multi-line corrected block).
// --------------------------------------------------------------------------

function fallbackJsSqlFix(line) {
  const asgn = /^(\s*)(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(.+)$/.exec(line);
  if (asgn) {
    const segs = tokenizeConcat(asgn[3]);
    const params = segs.filter((s) => s.x !== undefined).map((s) => s.x.trim());
    const literals = segs.filter((s) => s.s !== undefined).map((s) => s.s);
    const sql = literals.join("?");
    if (params.length && hasSqlKeywords(sql)) {
      const cleanedSql = sql.replace(/\s+/g, " ").trim();
      return `${asgn[1]}const ${asgn[2]} = ${JSON.stringify(cleanedSql)};\n${asgn[1]}const ${asgn[2]}Params = [${params.join(", ")}];`;
    }
  }
  return line.replace(/\+\s*([A-Za-z_$][\w$.]*)/g, (mm, v) => `? /* bind ${v} */`);
}

function fixSqlNode(line) {
  const m = /\b((?:db\.|pool\.|connection\.|client\.|sess\.|knex\.|sequelize\.|conn\.|app\.)?(?:query|execute|raw|run|all))\s*\(/i.exec(line);
  if (!m) return fallbackJsSqlFix(line);
  const openIdx = line.indexOf("(", m.index);
  const closeIdx = findMatchingParen(line, openIdx);
  if (closeIdx < 0) return fallbackJsSqlFix(line);
  const inner = line.slice(openIdx + 1, closeIdx);
  const args = splitTopLevel(inner).map((a) => a.trim()).filter(Boolean);
  if (!args.length) return fallbackJsSqlFix(line);
  const segs = tokenizeConcat(args[0]);
  const params = segs.filter((s) => s.x !== undefined).map((s) => s.x.trim());
  const literals = segs.filter((s) => s.s !== undefined).map((s) => s.s);
  const sql = literals.join("?");
  if (!params.length || !hasSqlKeywords(sql)) return fallbackJsSqlFix(line);
  const cleanedSql = sql.replace(/\s+/g, " ").trim();
  const paramArr = `[${params.join(", ")}]`;
  const restArgs = args.slice(1);
  const tail = restArgs.length ? `, ${restArgs.join(", ")}` : "";
  return `${line.slice(0, m.index)}${m[1]}(${JSON.stringify(cleanedSql)}, ${paramArr}${tail})${line.slice(closeIdx + 1)}`;
}

function parsePythonSql(first) {
  const trimmed = first.trim();
  const fMatch = /^f(["'])/.exec(trimmed);
  if (fMatch && /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)/i.test(trimmed)) {
    const q = fMatch[1];
    let close = -1;
    let esc = false;
    for (let i = 2; i < trimmed.length; i++) {
      if (esc) { esc = false; continue; }
      if (trimmed[i] === "\\") { esc = true; continue; }
      if (trimmed[i] === q) { close = i; break; }
    }
    if (close < 0) return null;
    const body = trimmed.slice(2, close);
    const parts = splitFString(body);
    if (!parts.params.length) return null;
    return {
      sql: parts.literals.join("%s").replace(/\s+/g, " ").trim(),
      params: parts.params.filter((p) => p && p.length),
    };
  }
  const pct = findTopLevelPercent(trimmed);
  if (pct >= 0) {
    const fmt = trimmed.slice(0, pct);
    const right = trimmed.slice(pct + 1).trim();
    const fmtMatch = /^["']([\s\S]*?)["']\s*$/.exec(fmt);
    if (!fmtMatch) return null;
    const sql = fmtMatch[1];
    let params = [];
    if (/^\(.*\)$/.test(right)) {
      const innerList = right.slice(1, right.lastIndexOf(")"));
      params = splitTopLevel(innerList).map((s) => s.trim()).filter(Boolean);
    } else if (right) {
      params = [right];
    }
    if (!params.length || !hasSqlKeywords(sql)) return null;
    return { sql: sql.replace(/\s+/g, " ").trim(), params };
  }
  const segs = tokenizeConcat(trimmed);
  const params = segs.filter((s) => s.x !== undefined).map((s) => s.x.trim());
  const literals = segs.filter((s) => s.s !== undefined).map((s) => s.s);
  const joined = literals.join("%s");
  if (!params.length || !hasSqlKeywords(joined)) return null;
  return { sql: joined.replace(/\s+/g, " ").trim(), params };
}

function fixSqlPython(line) {
  const call = /\b([\w.]+\.(?:execute|executemany|executescript|\bexecute|executemany))\s*\(/.exec(line) || /\b((?:execute|executemany))\s*\(/.exec(line);
  if (call) {
    const callee = call[1];
    const openIdx = line.indexOf("(", call.index);
    const closeIdx = findMatchingParen(line, openIdx);
    if (closeIdx > 0) {
      const inner = line.slice(openIdx + 1, closeIdx);
      const args = splitTopLevel(inner).map((a) => a.trim()).filter(Boolean);
      const parsed = parsePythonSql(args[0]);
      if (parsed && parsed.params.length) {
        const paramTuple = `(${parsed.params.join(", ")},)`;
        const hasParamsArg = args.length >= 2 && args[1].startsWith("(");
        let content;
        if (hasParamsArg) {
          content = `${JSON.stringify(parsed.sql)}${args.slice(1).map((a) => ", " + a).join("")}`;
        } else {
          content = `${JSON.stringify(parsed.sql)}, ${paramTuple}${args.slice(1).map((a) => ", " + a).join("")}`;
        }
        return `${line.slice(0, call.index)}${callee}(${content})${line.slice(closeIdx + 1)}`;
      }
    }
  }
  const asgn = /^(\s*)([\w.]+)\s*=\s*(.+)$/.exec(line);
  if (asgn) {
    const parsed = parsePythonSql(asgn[3]);
    if (parsed && parsed.params.length) {
      return `${asgn[1]}${asgn[2]} = ${JSON.stringify(parsed.sql)};\n${asgn[1]}${asgn[2]}_params = (${parsed.params.join(", ")},)`;
    }
  }
  return line;
}

function fixSqlPhp(line) {
  const m = /(?:mysqli_query|query|exec|prepare)\s*\(/.exec(line);
  if (!m) return line;
  const openIdx = line.indexOf("(", m.index);
  const closeIdx = findMatchingParen(line, openIdx);
  if (closeIdx < 0) return line;
  const inner = line.slice(openIdx + 1, closeIdx);
  const segs = tokenizeConcat(inner);
  const params = segs.filter((s) => s.x !== undefined).map((s) => s.x.trim());
  const literals = segs.filter((s) => s.s !== undefined).map((s) => s.s);
  const sqlText = literals.join("?");
  if (!params.length || !hasSqlKeywords(sqlText)) return line;
  const sql = sqlText.replace(/\s+/g, " ").trim();
  const p = params[0] || "$value";
  return `$stmt = $conn->prepare(${JSON.stringify(sql)});\n$stmt->bind_param("s", ${p});\n$stmt->execute();`;
}

function fixCommandInjection(line) {
  const m = /\b(?:exec|execSync|child_process\.exec|execFile|spawn)\s*\(|(?:os\.system|os\.popen)\s*\(|subprocess\.(?:call|run|Popen)\s*\(/.exec(line);
  if (!m) return line;
  const openIdx = line.indexOf("(", m.index);
  const closeIdx = findMatchingParen(line, openIdx);
  if (closeIdx < 0) return line;
  const inner = line.slice(openIdx + 1, closeIdx);
  const args = splitTopLevel(inner).map((a) => a.trim()).filter(Boolean);
  if (!args.length) return line;
  const segs = tokenizeConcat(args[0]);
  const literals = segs.filter((s) => s.s !== undefined).map((s) => s.s);
  const params = segs.filter((s) => s.x !== undefined).map((s) => s.x.trim());
  if (!literals.length || !params.length) return line;
  const fullCmd = literals.join(" ");
  const tokens = fullCmd.split(/\s+/).filter(Boolean);
  const cmd = tokens[0] || "cmd";
  const staticArgs = tokens.slice(1);
  const restArgs = args.slice(1);
  const tail = restArgs.length ? `, ${restArgs.join(", ")}` : "";
  if (/os\.system|os\.popen|subprocess/i.test(line)) {
    const parts = [JSON.stringify(cmd)];
    for (const a of staticArgs) parts.push(JSON.stringify(a));
    for (const p of params) parts.push(p);
    return `subprocess.run([${parts.join(", ")}], check=True)`;
  }
  const argArr = [...staticArgs.map((a) => JSON.stringify(a)), ...params];
  return `${line.slice(0, m.index)}execFile(${JSON.stringify(cmd)}, [${argArr.join(", ")}]${tail})${line.slice(closeIdx + 1)}`;
}

function fixXss(line) {
  if (line.includes(".innerHTML") || /\.html\s*\(/.test(line)) {
    return line.replace(/\.innerHTML\s*=/g, ".textContent =").replace(/\.html\s*\(/, ".text(");
  }
  if (line.includes("dangerouslySetInnerHTML")) {
    return line.replace(/__html:\s*([a-zA-Z0-9_.]+)/, "__html: DOMPurify.sanitize($1)");
  }
  if (/v-html\s*=/.test(line)) {
    return line.replace(/v-html\s*=\s*["']?([^"',}]+)/, 'v-text="$1"');
  }
  if (line.includes("res.send")) {
    return line.replace(/res\.send\((.*)\)/, "res.type('html').send(escapeHtml($1))");
  }
  if (line.includes("document.write")) {
    return line.replace(/document\.write\((.*)\)/, "document.body.append(document.createTextNode($1))");
  }
  return line;
}

function fixPathTraversal(line) {
  return line.replace(/fs\.readFile\(([^,]+)/, "const safePath = path.resolve(SAFE_DIR, path.basename($1));\nfs.readFile(safePath");
}

function isHttpCall(line) {
  return (
    /\bfetch\s*\(/i.test(line) ||
    /\baxios\.(?:get|post|put|patch|request)\s*\(/i.test(line) ||
    /\b(?:request|got)\.(?:get|post|put|patch|request)\s*\(/i.test(line) ||
    /\b(?:http|https)\.(?:get|post|request)\s*\(/i.test(line) ||
    /\brequests\.(?:get|post|put|patch|request|head)\s*\(/i.test(line) ||
    /\burllib\.request\.urlopen\s*\(/i.test(line) ||
    /\bsocket\.create_connection\s*\(/i.test(line) ||
    /\bURL\s*\(\s*["']/.test(line)
  );
}

function isUserInput(line) {
  return (
    /(?:req\.|query\.|params\.|body\.|request\.|args\[|form\[)/i.test(line) ||
    /["'][^"']*["']\s*\+/i.test(line) ||
    /\$\{/.test(line) ||
    /\bf["']/.test(line)
  );
}

// --------------------------------------------------------------------------
// 1. SECRET & CREDENTIAL DETECTORS
// --------------------------------------------------------------------------
const SECRET_RULES = [
  {
    name: "AWS Access Key ID",
    category: "Secrets Exposure",
    severity: "Critical",
    cwe: "CWE-798: Use of Hard-coded Credentials",
    owasp: "A07:2021-Identification and Authentication Failures",
    regex: /AKIA[0-9A-Z]{16}/g,
    explanation: "An AWS Access Key ID is hardcoded directly in the source code. Anyone with access to the code can identify the cloud account and potentially access cloud resources.",
    impact: "Unauthorized access to AWS infrastructure, data exfiltration, compute resource hijacking, and high cloud billing costs.",
    fix: "Remove the hardcoded key. Store it in an environment variable (e.g. AWS_ACCESS_KEY_ID) or use IAM roles / AWS Secrets Manager.",
    makeCorrection: (line) => line.replace(/["']AKIA[0-9A-Z]{16}["']/g, "process.env.AWS_ACCESS_KEY_ID || os.getenv('AWS_ACCESS_KEY_ID')"),
  },
  {
    name: "Hardcoded API Key",
    category: "Secrets Exposure",
    severity: "Critical",
    cwe: "CWE-798: Use of Hard-coded Credentials",
    owasp: "A07:2021-Identification and Authentication Failures",
    regex: /(?:api[_-]?key|apikey|secret[_-]?key|auth[_-]?token|access[_-]?token|private[_-]?key)\s*[:=]\s*["']([A-Za-z0-9_\-!@#$%^&*+/]{16,})["']/gi,
    explanation: "The API key or authentication token is hardcoded in the source code. This can lead to unauthorized access to external services or internal APIs if the code is exposed publicly or shared.",
    impact: "Attacker can extract the API key and misuse it, leading to data theft, quota exhaustion, unauthorized actions, or financial loss.",
    fix: "Store API keys in environment variables (.env file) or a secure secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
    makeCorrection: (line) => {
      return line.replace(/(["'])[A-Za-z0-9_\-!@#$%^&*+/]{16,}\1/g, "process.env.API_KEY || os.getenv('API_KEY')");
    },
  },
  {
    name: "Stripe Secret / Live API Key",
    category: "Secrets Exposure",
    severity: "Critical",
    cwe: "CWE-798: Use of Hard-coded Credentials",
    owasp: "A07:2021-Identification and Authentication Failures",
    regex: /sk_(?:live|test)_[0-9a-zA-Z]{24,}/g,
    explanation: "A Stripe API key is exposed in plaintext. A live key gives full access to payment processing, customer details, and financial transactions.",
    impact: "Direct financial theft, fraudulent refunds, unauthorized charges, and customer credit card / PII data exposure.",
    fix: "Move Stripe keys into environment variables (STRIPE_SECRET_KEY) and never commit them to version control.",
    makeCorrection: (line) => line.replace(/["']sk_(?:live|test)_[0-9a-zA-Z]{24,}["']/g, "process.env.STRIPE_SECRET_KEY || os.getenv('STRIPE_SECRET_KEY')"),
  },
  {
    name: "Google API Key",
    category: "Secrets Exposure",
    severity: "High",
    cwe: "CWE-798: Use of Hard-coded Credentials",
    owasp: "A07:2021-Identification and Authentication Failures",
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    explanation: "A Google API key is embedded directly in the source code, allowing unauthorized consumption of Google Cloud APIs and services.",
    impact: "Quota exhaustion, unexpected GCP billing charges, and unauthorized access to configured Google Cloud APIs.",
    fix: "Restrict API key usage in Google Cloud Console by HTTP referrers/IPs, and load it from environment variables.",
    makeCorrection: (line) => line.replace(/["']AIza[0-9A-Za-z\-_]{35}["']/g, "process.env.GOOGLE_API_KEY || os.getenv('GOOGLE_API_KEY')"),
  },
  {
    name: "GitHub Personal Access Token",
    category: "Secrets Exposure",
    severity: "Critical",
    cwe: "CWE-798: Use of Hard-coded Credentials",
    owasp: "A07:2021-Identification and Authentication Failures",
    regex: /gh[pousr]_[A-Za-z0-9]{36,}/g,
    explanation: "A GitHub Personal Access Token or OAuth token is hardcoded in the codebase, granting access to repositories, organizations, and actions.",
    impact: "Source code theft, unauthorized commits, malicious release modifications, and supply chain compromise.",
    fix: "Revoke the token immediately in GitHub settings and load tokens from GitHub Secrets or environment variables.",
    makeCorrection: (line) => line.replace(/["']gh[pousr]_[A-Za-z0-9]{36,}["']/g, "process.env.GITHUB_TOKEN || os.getenv('GITHUB_TOKEN')"),
  },
  {
    name: "Hardcoded Database Password / Connection String",
    category: "Secrets Exposure",
    severity: "Critical",
    cwe: "CWE-798: Use of Hard-coded Credentials",
    owasp: "A07:2021-Identification and Authentication Failures",
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^:\s]+:([^@\s]+)@[^\s"']+/gi,
    explanation: "A database connection URI with embedded plaintext username and password credentials is hardcoded in the code.",
    impact: "Complete database takeover, unauthorized database modifications, data destruction, and data leaks.",
    fix: "Use environment variables (DATABASE_URL) and separate credentials from database host configuration.",
    makeCorrection: (line) => line.replace(/(["'])(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql):\/\/[^\1]+?\1/g, "process.env.DATABASE_URL || os.getenv('DATABASE_URL')"),
  },
  {
    name: "RSA / Private Key Block",
    category: "Secrets Exposure",
    severity: "Critical",
    cwe: "CWE-312: Cleartext Storage of Sensitive Information",
    owasp: "A02:2021-Cryptographic Failures",
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    explanation: "An asymmetric private cryptographic key is embedded in plaintext in source code.",
    impact: "Impersonation of the server, TLS decryption, SSH server access, or forging cryptographic signatures.",
    fix: "Load private keys from secure file paths with restricted permissions or a key management vault.",
    makeCorrection: (line) => "// Load private key securely from vault or env path\nconst privateKey = fs.readFileSync(process.env.PRIVATE_KEY_PATH, 'utf8');",
  },
  {
    name: "Generic Bearer / JWT Token",
    category: "Secrets Exposure",
    severity: "High",
    cwe: "CWE-798: Use of Hard-coded Credentials",
    owasp: "A07:2021-Identification and Authentication Failures",
    regex: /Bearer\s+[A-Za-z0-9\-_~+/]{25,}={0,2}/g,
    explanation: "A hardcoded Bearer token is present in the source file, which may allow persistent authorization to services.",
    impact: "Session hijacking and unauthorized API access until token expiration.",
    fix: "Retrieve authorization tokens dynamically via OAuth/Auth flow and store in secure storage.",
    makeCorrection: (line) => line.replace(/Bearer\s+[A-Za-z0-9\-_~+/]{25,}={0,2}/g, "Bearer ${authToken}"),
  },
];

// --------------------------------------------------------------------------
// 2. CODE VULNERABILITY DETECTORS (all 20 categories)
// --------------------------------------------------------------------------
const CODE_RULES = [
  {
    name: "SQL Injection",
    category: "Injection Flaws",
    severity: "Critical",
    cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    owasp: "A03:2021-Injection",
    test: (line) => {
      return (
        /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)\s+[^;]*?(?:\+\s*[A-Za-z0-9_$]|\$\{|["']\s*%\s*\(?[A-Za-z0-9_$.]|\bformat\(|\bf["'])/i.test(line) ||
        /(?:query|execute|raw|db\.run|cursor\.execute)\s*\(\s*["'`].*(?:SELECT|INSERT|UPDATE|DELETE).*(?:\$\{|["']\s*\+)/i.test(line) ||
        /(?:query|execute)\s*=\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE).*["']\s*\+\s*[a-zA-Z0-9_$]+/i.test(line) ||
        /(?:execute|executeBatch|executeUpdate)\s*\(\s*["'].*(?:SELECT|INSERT|UPDATE|DELETE).*["']\s*\+/i.test(line)
      );
    },
    explanation: "User input is directly concatenated or interpolated into a raw SQL query string without parameterization.",
    impact: "Attackers can manipulate query logic to bypass authentication, extract entire databases, modify sensitive records, or execute administrative commands.",
    fix: "Use parameterized queries (prepared statements) with placeholders (? or $1) or an ORM that safely binds variables.",
    makeCorrection: (line) => {
      if (/[\w.]+\.(?:execute|executemany|executescript)\s*\(|\.execute\s*\(|\bf["']/.test(line) || /%/.test(line) && /\.execute|query\s*=\s*["']/.test(line)) {
        return fixSqlPython(line);
      }
      if (/\$[a-zA-Z_]|\bmysqli_query|->\s*(?:query|prepare|exec)\s*\(|\bPDO\b|mysqli_/.test(line)) {
        return fixSqlPhp(line);
      }
      return fixSqlNode(line);
    },
  },
  {
    name: "Cross-Site Scripting (XSS)",
    category: "Injection Flaws",
    severity: "High",
    cwe: "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
    owasp: "A03:2021-Injection",
    test: (line) => {
      return (
        /\.innerHTML\s*=\s*(?!["'`][^<]*["'`])[a-zA-Z0-9_.]+/i.test(line) ||
        /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:\s*(?!sanitize)[a-zA-Z0-9_.]+/i.test(line) ||
        /document\.write\s*\(\s*(?!["'`][^<]*["'`])[a-zA-Z0-9_.]+/i.test(line) ||
        /v-html\s*=\s*["']?[^"'<>]{2,}/i.test(line) ||
        /res\.send\s*\(\s*["']<[a-z0-9]+>.*["']\s*\+/i.test(line) ||
        /res\.send\s*\(\s*`.*<[a-z0-9]+>.*\$\{/i.test(line)
      );
    },
    explanation: "Unsanitized user-controlled data is rendered directly into the DOM or HTML response without proper encoding.",
    impact: "Execution of malicious JavaScript in victim browsers, leading to session hijacking, credential theft, DOM defacement, and phishing.",
    fix: "Use safe DOM APIs such as textContent or innerText, escape HTML entities, or use a sanitizer library like DOMPurify.",
    makeCorrection: fixXss,
  },
  {
    name: "OS Command Injection",
    category: "Injection Flaws",
    severity: "Critical",
    cwe: "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    owasp: "A03:2021-Injection",
    test: (line) => {
      const callHead = /(?:exec|execSync|child_process\.exec|system|os\.system|os\.popen|subprocess\.(?:call|run|Popen))\s*\(/i;
      if (!callHead.test(line)) return false;
      if (/\$\{/.test(line)) return true;
      if (/\+\s*[A-Za-z0-9_$]/.test(line)) return true;
      if (/['"`][^'"`]*['"`]\s*[)%]/.test(line) === false && /\b(?:exec|execSync)\s*\(\s*[A-Za-z_$][\w$.]+/.test(line)) return true;
      return false;
    },
    explanation: "User input is concatenated into an OS shell execution string, allowing shell metacharacters (;, |, &&) to execute arbitrary commands.",
    impact: "Full server compromise, unauthorized file access, remote shell creation, and lateral network movement.",
    fix: "Use execFile or spawn with command and arguments separated into an array, without invoking a system shell.",
    makeCorrection: fixCommandInjection,
  },
  {
    name: "Path Traversal / Arbitrary File Read",
    category: "Injection Flaws",
    severity: "High",
    cwe: "CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    owasp: "A01:2021-Broken Access Control",
    test: (line) => {
      const api =
        /fs\.(?:readFile|readFileSync|createReadStream|open|openSync)\s*\(/i.test(line) ||
        /res\.sendFile\s*\(|sendFile\s*\(/i.test(line) ||
        (/\.read_text\s*\(|\.read_bytes\s*\(|open\s*\(/.test(line) && /file|path|static|user|upload/.test(line));
      if (!api) return false;
      if (/(?:req\.|params\.|query\.|body\.|request\.|form\[|args\[|arg\.|config\.)/i.test(line)) return true;
      if (/\+\s*[A-Za-z_$][\w$]*/.test(line)) return true;
      if (/\$\{|f["']/.test(line)) return true;
      const m0 = /(?:readFile|readFileSync|createReadStream|open|openSync|sendFile|read_text|read_bytes)\s*\(\s*([A-Za-z_$][\w$.]*)/i.exec(line);
      if (m0 && /^(?:file|filename|filePath|path|name|url|input|dir|directory|location|upload|route)$/i.test(m0[1] || "")) return true;
      return false;
    },
    explanation: "User-supplied file paths are accessed without canonicalization or validation against a directory root, allowing ../ traversal.",
    impact: "Attackers can read sensitive server files, configuration files (.env, /etc/passwd), and source code.",
    fix: "Validate filenames against an allowlist, strip traversal sequences (../), and resolve paths relative to a safe base directory.",
    makeCorrection: fixPathTraversal,
  },
  {
    name: "Dangerous Code Evaluation (eval / Function)",
    category: "Security Misconfigurations",
    severity: "Critical",
    cwe: "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')",
    owasp: "A03:2021-Injection",
    test: (line) => {
      return (
        /\beval\s*\(\s*(?!["'][^"']*["']\s*\))[a-zA-Z0-9_.]+/i.test(line) ||
        /new\s+Function\s*\(\s*.*[a-zA-Z0-9_.]+\s*\)/i.test(line) ||
        /\beval\s*\(\s*input/i.test(line)
      );
    },
    explanation: "Dynamic code execution via eval() or the Function constructor on untrusted input allows arbitrary code execution.",
    impact: "Remote code execution, access to application memory, environment variables, and backend control.",
    fix: "Avoid eval() entirely. Use JSON.parse() for structured data or a dedicated expression parser with sandboxing.",
    makeCorrection: (line) => line.replace(/eval\(([^)]+)\)/, "JSON.parse($1)"),
  },
  {
    name: "Weak Password Hashing / Broken Cryptography",
    category: "Insecure Authentication",
    severity: "High",
    cwe: "CWE-916: Use of Password Hash With Insufficient Computational Effort",
    owasp: "A02:2021-Cryptographic Failures",
    test: (line) => {
      return (
        /createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/i.test(line) ||
        /hashlib\.(?:md5|sha1)\s*\(/i.test(line) ||
        /password.*==.*md5/i.test(line)
      );
    },
    explanation: "MD5 or SHA1 is used for cryptographic operations or password storage. These algorithms are vulnerable to collision attacks and brute-force cracking.",
    impact: "Rapid cracking of user passwords using rainbow tables and GPUs, leading to unauthorized account access.",
    fix: "Use modern adaptive hashing algorithms like bcrypt, Argon2, or PBKDF2 with salt for passwords, and SHA-256/SHA-512 for data integrity.",
    makeCorrection: (line) => {
      if (line.includes("createHash")) {
        return line.replace(/createHash\(["'](?:md5|sha1)["']\)/, "createHash('sha256') /* Or use bcrypt for passwords: await bcrypt.hash(password, 12) */");
      }
      if (line.includes("hashlib")) {
        return line.replace(/hashlib\.(?:md5|sha1)\(/, "hashlib.sha256(");
      }
      return "const hashedPassword = await bcrypt.hash(password, 12);";
    },
  },
  {
    name: "Hardcoded Admin Credentials / Insecure Authentication",
    category: "Insecure Authentication",
    severity: "Critical",
    cwe: "CWE-287: Improper Authentication",
    owasp: "A07:2021-Identification and Authentication Failures",
    test: (line) => {
      return (
        /(?:username|user|login)\s*===?\s*["']admin["']\s*&&\s*(?:password|pass|pwd)\s*===?\s*["'][^"']+["']/i.test(line) ||
        /(?:password|pass|pwd)\s*===?\s*["']admin123["']/i.test(line)
      );
    },
    explanation: "Hardcoded administrative credentials in application logic allow unauthorized users to gain administrative privileges without proper verification.",
    impact: "Complete authentication bypass and administrative takeover of the system.",
    fix: "Authenticate users against a secure database with hashed passwords and role-based access control.",
    makeCorrection: (line) => "const isValid = await verifyUserCredentials(username, password);",
  },
  {
    name: "Insecure TLS / Certificate Validation Disabled",
    category: "Security Misconfigurations",
    severity: "High",
    cwe: "CWE-295: Improper Certificate Validation",
    owasp: "A05:2021-Security Misconfiguration",
    test: (line) => {
      return (
        /rejectUnauthorized\s*:\s*false/i.test(line) ||
        /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0["']?/i.test(line) ||
        /ssl_verify\s*=\s*False/i.test(line) ||
        /verify\s*=\s*False/i.test(line)
      );
    },
    explanation: "TLS/SSL certificate validation is explicitly disabled, allowing connections to unverified or forged certificates.",
    impact: "Man-in-the-middle (MITM) attacks, enabling interception and tampering of encrypted traffic and credentials.",
    fix: "Enable strict TLS certificate validation (rejectUnauthorized: true or verify=True) in all environments.",
    makeCorrection: (line) => line.replace(/rejectUnauthorized\s*:\s*false/g, "rejectUnauthorized: true")
                                 .replace(/verify\s*=\s*False/g, "verify=True")
                                 .replace(/NODE_TLS_REJECT_UNAUTHORIZED.*0.*/g, "NODE_TLS_REJECT_UNAUTHORIZED = '1'"),
  },
  {
    name: "Sensitive Information Disclosure / Debug Leakage",
    category: "Information Disclosure",
    severity: "Medium",
    cwe: "CWE-209: Generation of Error Message Containing Sensitive Information",
    owasp: "A05:2021-Security Misconfiguration",
    test: (line) => {
      return (
        /res\.(?:status\s*\([^)]*\)\s*\.\s*)?(?:send|json)\s*\(\s*\{[\s\S]*?(?:stack|err\.stack|error:\s*err)[\s\S]*?\}\s*\)/i.test(line) ||
        /res\.send\s*\(\s*JSON\.stringify\s*\(\s*err\s*\)\s*\)/i.test(line) ||
        /DEBUG\s*=\s*True/i.test(line)
      );
    },
    explanation: "Internal error stack traces or sensitive details are sent directly in API responses or verbose debug is left enabled.",
    impact: "Leaks database schemas, file system paths, internal dependencies, and sensitive credentials to unauthorized clients.",
    fix: "Sanitize error responses in production to return generic error messages, and avoid logging sensitive parameters.",
    makeCorrection: (line) => {
      if (line.includes("err.stack") || line.includes("stack:")) {
        return line.replace(/stack:\s*err\.stack/g, "message: 'An internal error occurred'");
      }
      if (line.includes("JSON.stringify")) {
        return line.replace(/JSON\.stringify\s*\(\s*err\s*\)/, "{ error: 'Internal server error' }");
      }
      return line.replace(/DEBUG\s*=\s*True/, "DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'");
    },
  },
  {
    name: "Sensitive Data in Logs",
    category: "Information Disclosure",
    severity: "Medium",
    cwe: "CWE-532: Insertion of Sensitive Information into Log File",
    owasp: "A09:2021-Security Logging and Monitoring Failures",
    test: (line) => {
      if (!/console\.(?:log|debug|info|warn|error)\s*\(/.test(line)) return false;
      return /password|passwd|pwd|secret|apiKey|api_key|token|authorization|set-cookie|session|credit.?card|cvv|ssn|private[_-]?key/i.test(line);
    },
    explanation: "Sensitive credentials or personal data are written to application logs, where they can be exfiltrated or used by an attacker.",
    impact: "Credential theft, session hijacking, PII exposure, and compliance violations.",
    fix: "Remove secrets from log lines; log only redacted values or a correlation id.",
    makeCorrection: (line) => {
      return line.replace(/(console\.(?:log|debug|info|warn|error)\s*\(\s*)[^)]*\)/, "$1redactSensitive(obj) // strip secrets before logging");
    },
  },
  {
    name: "Permissive CORS Configuration",
    category: "Security Misconfigurations",
    severity: "Medium",
    cwe: "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
    owasp: "A05:2021-Security Misconfiguration",
    test: (line) => {
      return (
        /cors\s*\(\s*\{\s*origin\s*:\s*["']\*["']\s*,\s*credentials\s*:\s*true/i.test(line) ||
        /setHeader\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*["']\*["']\s*\)/i.test(line)
      );
    },
    explanation: "CORS is configured to allow all origins ('*') while enabling credentials, allowing untrusted domains to make authenticated requests.",
    impact: "Malicious websites visited by authenticated users can send cross-origin requests and read private user data.",
    fix: "Specify an explicit list of trusted origin domains instead of wildcard '*' when credentials are required.",
    makeCorrection: (line) => line.replace(/origin\s*:\s*["']\*["']/g, "origin: ['https://yourdomain.com']"),
  },
  {
    name: "Hardcoded Password / Plaintext Credential",
    category: "Secrets Exposure",
    severity: "Critical",
    cwe: "CWE-798: Use of Hard-coded Credentials",
    owasp: "A07:2021-Identification and Authentication Failures",
    test: (line) => {
      const hit =
        /(?:\.password|\.passwd|\.pwd|\.connection_string|\b(?:password|passwd|pwd|pass))\s*=\s*["'][^"']{3,}["']/i.test(line) ||
        /(?:["']password["']|\bpassword|\.password|\.pwd)\s*:\s*["'][^"']{3,}["']/i.test(line);
      if (!hit) return false;
      return !/process\.env|os\.getenv|getenv\(|\.env\b|console\.|===|!==/.test(line);
    },
    explanation: "A plaintext password or credential is assigned directly in source code instead of being derived from a secure store.",
    impact: "Exposed credentials allow unauthorized access to databases, third-party services, and user accounts.",
    fix: "Load credentials from environment variables or a secrets manager at runtime, never hardcode them.",
    makeCorrection: (line) => line.replace(/["'][^"']{3,}["']/, "process.env.DB_PASSWORD || os.getenv('DB_PASSWORD')"),
  },
  {
    name: "Insecure Random Number Generation",
    category: "Security Misconfigurations",
    severity: "High",
    cwe: "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",
    owasp: "A02:2021-Cryptographic Failures",
    test: (line) => {
      const seckey = /password|passwd|pwd|token|otp|secret|salt|nonce|hmac|sign|auth|csrf|reset|session|api[_-]?key/i;
      return (
        (/\bMath\.random\s*\(/.test(line) || /\bcrypto\.pseudoRandomBytes\s*\(/.test(line)) && seckey.test(line) ||
        (/\brandom\.(?:random|uniform|randint|choice|SystemRandom)\s*\(/.test(line) || /\brandom\s*=\s*Random\s*\(/.test(line)) && seckey.test(line)
      );
    },
    explanation: "A predictable pseudo-random number generator is used to derive a security-sensitive value such as a token, OTP, password, salt, or session id.",
    impact: "Attackers can predict generated tokens to reset passwords, hijack sessions, or bypass CSRF/OTP protections.",
    fix: "Use a cryptographically secure generator: crypto.randomBytes()/randomInt in Node, secrets.token_* in Python.",
    makeCorrection: (line) => {
      if (/\bMath\.random/.test(line)) {
        return line.replace(/\bMath\.random\s*\([^)]*\)/g, "crypto.randomInt(0, 1_000_000_000)");
      }
      if (/\brandom\.[a-zA-Z]+\s*\(/.test(line)) {
        return line.replace(/\brandom\.(?:random|uniform|randint|choice|SystemRandom)\s*\([^)]*\)/g, "secrets.token_hex(16)");
      }
      return line;
    },
  },
  {
    name: "Broken Cryptography (Weak Algorithm / ECB / Small Key)",
    category: "Security Misconfigurations",
    severity: "High",
    cwe: "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
    owasp: "A02:2021-Cryptographic Failures",
    test: (line) => {
      if (/createCipher(?:iv)?\s*\(\s*["'](?:des|3des|des-ede|des3|des-ede3|rc4|arc4|bf|blowfish|aes-128-ecb|aes-192-ecb|aes-256-ecb|des-ecb)["']/i.test(line)) return true;
      if (/Cipher\.getInstance\s*\(\s*["'](?:DES|DESede|RC4|Blowfish|AES\/ECB|RSA\/ECB)/i.test(line)) return true;
      if (/(?:["'](?:DES|3DES|DESede|RC4|ArcFour|Blowfish|aes-\d+-ecb|des\b)["'])(?=.*(?:cipher|decipher|encrypt|decrypt))/i.test(line)) return true;
      const keySz = /modulusLength\s*:\s*(\d+)/i.exec(line) || /keySize\s*[:=]\s*(\d+)/i.exec(line);
      if (keySz && Number(keySz[1]) < 2048 && /rsa|key|pair/i.test(line)) return true;
      if (/createCipheriv\s*\([^,]+,\s*["']|\biv\s*[:=]\s*["'][A-Za-z0-9=]{6,}["']/.test(line) && /cipher|encrypt|iv/i.test(line)) return true;
      return false;
    },
    explanation: "Weak or obsolete cryptography (DES, 3DES, RC4, ECB mode, small RSA keys, or a hardcoded IV) is used to protect data.",
    impact: "Encrypted data can be decrypted or tampered with, and signing keys can be recovered — defeating the protection.",
    fix: "Use modern algorithms with authenticated modes, e.g. AES-256-GCM with a random IV, and RSA keys >= 2048 bits.",
    makeCorrection: (line) => {
      if (/modulusLength|keySize/.test(line)) {
        return line.replace(/modulusLength\s*:\s*\d+/i, "modulusLength: 4096").replace(/keySize\s*[:=]\s*\d+/i, "keySize: 2048");
      }
      if (/Cipher\.getInstance/.test(line)) {
        return line.replace(/Cipher\.getInstance\s*\(\s*["'][^"']+["']/, "Cipher.getInstance(\"AES/GCM/NoPadding\"");
      }
      if (/(?:iv\s*[:=]|createCipheriv\s*\([^,]+,\s*)["']/.test(line)) {
        return line.replace(/["'][A-Za-z0-9=]{6,}["']/, "crypto.randomBytes(16).toString('hex') /* random IV */");
      }
      return line.replace(/["'](?:des|3des|des-ede|des3|rc4|arc4|bf|blowfish|aes-\d+-ecb)["']/gi, "'aes-256-gcm'");
    },
  },
  {
    name: "Open Redirect",
    category: "Broken Access Control",
    severity: "Medium",
    cwe: "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
    owasp: "A01:2021-Broken Access Control",
    test: (line) => {
      return (
        /res\.redirect\s*\(\s*(?:\$\{|["'][^"']*["']\s*\+|(?:req|query|params|body)\.[a-zA-Z0-9_.]+|location\b)/i.test(line) ||
        /(?:window\.location|location\.href)\s*=\s*(?:["'][^"']*["']\s*\+|\$\{|(?:location\.search|location\.hash|url)\b)/i.test(line) ||
        /window\.open\s*\(\s*(?:["'][^"']*["']\s*\+|url\b|req\.)/i.test(line) ||
        /redirect\s*\(\s*(?:request\.(?:args|form|values)|flask\.request)/i.test(line) ||
        /\breturn\s+redirect\s*\(\s*url\b/i.test(line)
      );
    },
    explanation: "An unvalidated redirect target is taken from user input, allowing an attacker to send victims to malicious sites.",
    impact: "Phishing, credential theft, and trust abuse using a legitimate domain as a redirector.",
    fix: "Validate redirect targets against an allowlist of internal paths/hosts before redirecting.",
    makeCorrection: (line) => {
      if (/res\.redirect|return\s+redirect|redirect\s*\(/.test(line)) {
        return 'const SAFE_REDIRECT = (u, req) => /^\\/(?!\\/)/.test(u) ? u : "/";\nres.redirect(SAFE_REDIRECT(url, req));';
      }
      return line.replace(/(window\.location|location\.href)\s*=\s*(.*)/, "$1 = sanitizeUrl($2)").replace(/window\.open\s*\(\s*(.*)\)/, "window.open(sanitizeUrl($1))");
    },
  },
  {
    name: "Insecure File Upload Handling",
    category: "Security Misconfigurations",
    severity: "High",
    cwe: "CWE-434: Unrestricted Upload of File with Dangerous Type",
    owasp: "A08:2021-Software and Data Integrity Failures",
    test: (line) => {
      if (/upload\.(?:single|array|fields)\s*\(/.test(line) && !/fileFilter|limits|multer/.test(line)) return true;
      if (/multer\(|request\.files\[|request\.FILES\[|req\.files\[/.test(line) && !/fileFilter/.test(line)) return true;
      if (/move_uploaded_file\s*\(/.test(line)) return true;
      if (/\.save\s*\([^)]*file\.originalname/.test(line)) return true;
      return false;
    },
    explanation: "File upload accepts files without validating type, extension, or size, which can be abused to upload malicious executables or scripts.",
    impact: "Remote code execution on the web server, website defacement, malware hosting, and supply-chain compromise.",
    fix: "Whitelist allowed extensions and MIME types, enforce a size limit, store files outside the web root, and serve them with safe headers.",
    makeCorrection: (line) => {
      return "// Validate before save: whitelist extensions + size limits + randomize stored name\nconst allowed = ['.jpg','.png','.pdf'];\nif (!allowed.includes(path.extname(file.originalname).toLowerCase()) || file.size > 2*1024*1024) return res.status(400).send('Invalid file');";
    },
  },
  {
    name: "Server-Side Request Forgery (SSRF)",
    category: "Injection Flaws",
    severity: "High",
    cwe: "CWE-918: Server-Side Request Forgery (SSRF)",
    owasp: "A10:2021-Server-Side Request Forgery",
    test: (line) => {
      if (!isHttpCall(line)) return false;
      if (/(?:req\.|query\.|params\.|body\.|request\.|args\[|form\[)/i.test(line)) return true;
      if (/\$\{|["'][^"']*["']\s*\+/.test(line)) return true;
      return false;
    },
    explanation: "The server makes an HTTP request to a URL derived from user input, allowing the attacker to probe or attack internal services.",
    impact: "Access to internal metadata endpoints (e.g. cloud instance metadata), Intranet services, and port scanning from the server.",
    fix: "Validate the request target against an allowlist of permitted hosts and block private/loopback/link-local ranges.",
    makeCorrection: (line) => {
      return "// SSRF-safe: reject private/loopback/link-local targets and non-https schemes\nconst target = new URL(url);\nif (!ALLOWED_HOSTS.has(target.hostname) || isPrivateIp(target.hostname)) throw new Error('Blocked URL');";
    },
  },
  {
    name: "Broken Authentication / Session Fixation",
    category: "Insecure Authentication",
    severity: "High",
    cwe: "CWE-384: Session Fixation",
    owasp: "A07:2021-Identification and Authentication Failures",
    test: (line) => {
      if (/[\w$]*(?:session(?:\.\w+)?|session_id|sessionId|sid|token)\s*[=:]\s*(?:req\.(?:body|query|params)\.[\w$.]+|body\.|data\.|\$\{)/i.test(line)) return true;
      if (/localStorage\.setItem\s*\(\s*["'](?:token|jwt|session|auth)["']/i.test(line)) return true;
      if (/[^a-z]session\s*\(\s*\{/.test(line) && /secret\s*:\s*["'][^"']{1,16}["']/.test(line)) return true;
      return false;
    },
    explanation: "Session identifiers are fixed from client-controlled values, stored insecurely in localStorage, or derived from weak hardcoded secrets.",
    impact: "Attacker fixation of a victim's session id, session hijacking, and account takeover.",
    fix: "Generate a fresh random session id via req.session.regenerate() after login and keep tokens in httpOnly cookies.",
    makeCorrection: (line) => {
      if (/localStorage\.setItem/.test(line)) {
        return line.replace(/(localStorage\.setItem)/, "/* store tokens in httpOnly cookies instead of localStorage */\n// $1");
      }
      if (/secret\s*:\s*["']/.test(line)) {
        return line.replace(/secret\s*:\s*["'][^"']+["']/, "secret: process.env.SESSION_SECRET");
      }
      return "// Regenerate the session id after login: req.session.regenerate(() => { ... })\n// Never accept a session id from the client";
    },
  },
  {
    name: "Broken Access Control / Privilege Escalation",
    category: "Broken Access Control",
    severity: "High",
    cwe: "CWE-285: Improper Authorization",
    owasp: "A01:2021-Broken Access Control",
    test: (line) => {
      return (
        /req\.(?:body|query|params)\.(?:isAdmin|is_admin|role|permissions?)\s*[=\)]/.test(line) ||
        /(?:user|currentUser|req\.user|session\.user)\.(?:isAdmin|role|permissions?)\s*=\s*(?:req\.|body\.|query\.|params\.|data\.|payload\.)/i.test(line) ||
        /if\s*\(\s*req\.(?:body|query|params)\.isAdmin\s*===?\s*true/i.test(line) ||
        /req\.params\.id\s*[);,}\s]+.*(?:findById|findOne|fetch)\s*\(/.test(line) && !/owner|belongs|isOwner|mine/i.test(line)
      );
    },
    explanation: "Privileges or roles are derived from client-supplied input (or object access is keyed on a user-controlled id without an ownership check).",
    impact: "Privilege escalation to admin, and direct object reference attacks letting users read or modify others' data.",
    fix: "Always derive roles from the server-side session and enforce ownership/authz checks on every object access.",
    makeCorrection: (line) => "// Derive role from the server-side session (req.session.user.role), never from client input\n// and verify ownership: if (item.ownerId !== req.session.user.id) return 403;",
  },
  {
    name: "Insecure Cookie / Session Configuration",
    category: "Security Misconfigurations",
    severity: "Medium",
    cwe: "CWE-1004: Sensitive Cookie Without 'HttpOnly' Attribute",
    owasp: "A05:2021-Security Misconfiguration",
    test: (line) => {
      if (/res\.cookie\s*\(/.test(line)) {
        if (/httpOnly\s*:\s*false|secure\s*:\s*false/i.test(line)) return true;
        if (!/httpOnly|sameSite/i.test(line)) return true;
      }
      return false;
    },
    explanation: "Cookies are written without security attributes (httpOnly, secure, sameSite), exposing session or auth data to scripts and transport sniffing.",
    impact: "Session hijacking via XSS, and token interception over plaintext connections.",
    fix: "Set httpOnly, secure and SameSite=Strict on all sensitive cookies; use express-session with secure cookies in production.",
    makeCorrection: (line) => {
      if (line.includes("{")) {
        return line.replace(/(\{[^}]*?\})(\s*\))/, "$1, httpOnly: true, secure: true, sameSite: 'strict'$2");
      }
      return line.replace(/\)(\s*;?\s*)$/, ", { httpOnly: true, secure: true, sameSite: 'strict' })$1");
    },
  },
  {
    name: "LDAP Injection",
    category: "Injection Flaws",
    severity: "High",
    cwe: "CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
    owasp: "A03:2021-Injection",
    test: (line) => {
      return (
        /ldap(?:js)?\.(?:search|query|bind|unbind)\s*\([^)]*(?:\+|`)/i.test(line) ||
        /(?:ActiveDirectory|ad)\.(?:find|search|authenticate)\s*\([^)]*(?:\+|`)/i.test(line) ||
        /(?:&\(uid=[^)]*\)\$\{|&\(cn=[^)]*\)\$\{|&\(uid=[^)]*[^)]*\)\s*\+\s*[a-zA-Z_$])/i.test(line) && /ldap|ad\.|search|bind/i.test(line)
      );
    },
    explanation: "User input is concatenated directly into an LDAP filter, allowing filter manipulation through special characters (*, |, &).",
    impact: "Authentication bypass, unauthorized directory reads, and access to organizational data.",
    fix: "Escape LDAP filter metacharacters with ldap.escapeFilter() (Node) or escape_filter_chars() (python-ldap3) before building the filter.",
    makeCorrection: (line) => "// Sanitize the LDAP filter: ldap.escapeFilter(userInput) / escape_filter_chars(userInput)\n// e.g. db.search(dn, `(uid=)`) with escaped values",
  },
  {
    name: "NoSQL Injection",
    category: "Injection Flaws",
    severity: "High",
    cwe: "CWE-943: Improper Neutralization of Special Elements in Data Query Logic",
    owasp: "A03:2021-Injection",
    test: (line) => {
      return (
        /\.(?:find|findOne|findById|updateOne|deleteOne|remove|aggregate|countDocuments)\s*\(\s*(?:req\.(?:body|query|params)|body|query|params|data\.)/gi.test(line) ||
        (/(?:\\$where|\\$gt|\\$gte|\\$lt|\\$lte|\\$ne|\\$in|\\$regex|\\$expr|\\$mod)\s*[:=]/.test(line) && /req\.|body\.|query|param|input/.test(line))
      );
    },
    explanation: "Raw user objects or operator strings are passed into NoSQL queries, allowing query-operator injection (e.g. $ne, $gt, $where).",
    impact: "Authentication bypass, unauthorized data access, and full collection exfiltration.",
    fix: "Never pass raw client objects into queries; whitelist allowed fields, parse values to the expected type (e.g. ObjectId), and validate input strictly.",
    makeCorrection: (line) => "// Do not pass raw user objects into queries — whitelist + type-check inputs\n// e.g. findOne({ _id: new ObjectId(String(id)) }) with ObjectId.isValid(id) check",
  },
  {
    name: "Prototype Pollution",
    category: "Injection Flaws",
    severity: "High",
    cwe: "CWE-1321: Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')",
    owasp: "A03:2021-Injection",
    test: (line) => {
      return (
        /Object\.assign\s*\(\s*[^,]+,\s*(?:req\.|body\.|query\.|params\.|data\.|JSON\.parse)/i.test(line) ||
        /\.\.\.(?:req\.(?:body|query|params)|body\.|query\.|params\.)/.test(line) &&
          /Object\.assign|merge|copy|extend|clone|\{\s*\.\.\./i.test(line) ||
        /(?:\.|["']?__proto__["']?\s*)(?:=|[:])/.test(line) &&
          /__proto__/.test(line) ||
        /\b(?:_|lodash|underscore|deepmerge|merge)\.?\s*merge\s*\(\s*(?:[^)]{0,60}?)?(?:req\.|body\.|query\.|data\.)/i.test(line)
      );
    },
    explanation: "Untrusted input is merged into objects without guarding '__proto__' / 'constructor.prototype', polluting the object prototype.",
    impact: "Denial of service, property injection, XSS, and in some engines remote code execution.",
    fix: "Avoid recursive merges of untrusted input; block keys like __proto__/constructor and use Object.freeze on prototypes or safe merge helpers.",
    makeCorrection: (line) => {
      if (/__proto__/.test(line)) {
        return line.replace(/["']?__proto__["']?\s*[:=]/g, "/* blocked */ 'x_proto' ");
      }
      return line.replace(/Object\.assign\s*\(\s*([^,]+),\s*([^)]+)\)/, "Object.assign($1, sanitizeObject($2))");
    },
  },
  {
    name: "Unsafe Deserialization",
    category: "Security Misconfigurations",
    severity: "Critical",
    cwe: "CWE-502: Deserialization of Untrusted Data",
    owasp: "A08:2021-Software and Data Integrity Failures",
    test: (line) => {
      return (
        /\bunserialize\s*\(/.test(line) ||
        /\bpickle\.(?:loads|load)\s*\(/.test(line) ||
        (/\byaml\.load\s*\(/.test(line) && !/SafeLoader/.test(line)) ||
        /JSON\.parse\s*\(\s*eval\s*\(/.test(line) ||
        /\beval\s*\(\s*input/i.test(line) ||
        /\brequire\(\s*["']node-serialize["']\s*\)/.test(line) ||
        /\.unserialize\s*\(/.test(line) ||
        /\bActionController\.parameters\.permit|Marshal\.load/.test(line)
      );
    },
    explanation: "Untrusted data is deserialized by an unsafe mechanism (pickle, unserialize, eval-based, unsafe YAML), which can execute arbitrary code during parsing.",
    impact: "Remote code execution on the server whenever an attacker controls the serialized payload.",
    fix: "Deserialize only trusted data; use JSON with a strict schema, YAML safe_load, and never pickle/unserialize client-supplied input.",
    makeCorrection: (line) => {
      if (/yaml\.load\s*\(/.test(line)) return line.replace(/yaml\.load\s*\(/, "yaml.safe_load(");
      if (/pickle\.|unserialize\s*\(/.test(line)) return "// Never deserialize untrusted data with pickle/unserialize\nconst parsed = JSON.parse(validatedJson); // use a strict schema instead";
      return "// Never eval or deserialize untrusted input — validate with a strict schema (e.g. JSON + ajv)";
    },
  },
  {
    name: "Missing CSRF Token Validation",
    category: "CSRF",
    severity: "High",
    cwe: "CWE-352: Cross-Site Request Forgery (CSRF)",
    owasp: "A01:2021-Broken Access Control",
    test: (line) => {
      const stateChanging = /(?:app\.(?:post|put|delete|patch)\s*\(|router\.(?:post|put|delete|patch)\s*\(|@(?:app|router)\.(?:post|put|delete|patch)\s*\(|\.method\s*=\s*["'](?:POST|PUT|DELETE|PATCH)["']|fetch\s*\([^)]*method\s*:\s*["'](?:POST|PUT|DELETE|PATCH)["'])/i;
      if (!stateChanging.test(line)) return false;
      if (/csrf|_token|csrfToken|csrfTokenName|x-csrf|x-xsrf/i.test(line)) return false;
      if (/helmet|csurf|csrf保护|csrfProtect/i.test(line)) return false;
      return true;
    },
    explanation: "State-changing HTTP endpoints (POST/PUT/DELETE) do not appear to validate a CSRF token, allowing cross-site request forgery attacks.",
    impact: "Attackers can trick authenticated users into performing unwanted state-changing actions (transfer funds, change email, delete data).",
    fix: "Use a CSRF middleware (e.g. csurf for Express, Django CSRF middleware) and include the token in all state-changing requests.",
    makeCorrection: (line) => "// Add CSRF protection: app.use(csurf({ cookie: true }));\n// Include csrfToken() in forms and send as X-CSRF-Token header",
  },
  {
    name: "Missing Security Headers",
    category: "Missing / Weak Security Headers",
    severity: "Medium",
    cwe: "CWE-693: Protection Mechanism Failure",
    owasp: "A05:2021-Security Misconfiguration",
    test: (line) => {
      const hasHelmet = /helmet\s*\(/.test(line) || /app\.use\s*\(\s*helmet/.test(line);
      const hasXFrame = /X-Frame-Options|frame-ancestors|x-frame-options/i.test(line);
      const hasCSP = /Content-Security-Policy|content-security-policy|csp/i.test(line);
      const hasHSTS = /Strict-Transport-Security|strict-transport-security|hsts/i.test(line);
      const hasXContent = /X-Content-Type-Options|x-content-type-options/i.test(line);
      const hasReferrer = /Referrer-Policy|referrer-policy/i.test(line);
      const hasPermissions = /Permissions-Policy|permissions-policy/i.test(line);
      if (hasHelmet || hasXFrame || hasCSP || hasHSTS || hasXContent || hasReferrer || hasPermissions) return false;
      if (/app\.listen|createServer|express\s*\(/.test(line) && !/helmet/i.test(line)) return true;
      return false;
    },
    explanation: "The web server or framework is started without setting essential security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).",
    impact: "Clickjacking, MIME sniffing attacks, mixed content, and lack of transport security enforcement.",
    fix: "Use helmet (Express) or django.middleware.security.SecurityMiddleware (Django) to set all standard security headers.",
    makeCorrection: (line) => "const helmet = require('helmet');\napp.use(helmet()); // Sets X-Frame-Options, CSP, HSTS, X-Content-Type-Options, etc.",
  },
  {
    name: "Weak Cryptographic Hash (MD5/SHA1 for Data Integrity)",
    category: "Cryptographic Failures",
    severity: "High",
    cwe: "CWE-328: Reversible One-Way Hash",
    owasp: "A02:2021-Cryptographic Failures",
    test: (line) => {
      if (/createHash\s*\(\s*["'](?:md5|sha1)["']\s*\)/i.test(line)) return true;
      if (/hashlib\.(?:md5|sha1)\s*\(/i.test(line)) return true;
      if (/\bMD5\b|\bSHA1\b|\bsha-1\b|\bmd5\b/.test(line) && /hash|digest|verify|sign|integrity/i.test(line)) return true;
      if (/SparkMD5|CryptoJS\.MD5|CryptoJS\.SHA1/i.test(line)) return true;
      return false;
    },
    explanation: "MD5 or SHA-1 is used for data integrity, signing, or verification. These algorithms are cryptographically broken and vulnerable to collision attacks.",
    impact: "Forged data can pass integrity checks, digital signatures can be duplicated, and certificate chains can be compromised.",
    fix: "Use SHA-256, SHA-3, or BLAKE2 for data integrity. For password hashing, use bcrypt, Argon2, or PBKDF2.",
    makeCorrection: (line) => {
      if (/createHash/.test(line)) return line.replace(/createHash\(["'](?:md5|sha1)["']\)/, "createHash('sha256')");
      if (/hashlib/.test(line)) return line.replace(/hashlib\.(?:md5|sha1)\(/, "hashlib.sha256(");
      return line.replace(/MD5|SHA1|sha-1|md5/gi, "SHA256");
    },
  },
  {
    name: "Insecure Session Management",
    category: "Broken Session Management",
    severity: "High",
    cwe: "CWE-613: Insufficient Session Expiration",
    owasp: "A07:2021-Identification and Authentication Failures",
    test: (line) => {
      if (/express-session|cookie-session|session\s*\(/.test(line) && /resave\s*:\s*false|saveUninitialized\s*:\s*true/i.test(line)) return true;
      if (/session\.cookie.*(?:maxAge|expires)\s*[:=]\s*(?:undefined|null|0|false)/i.test(line)) return true;
      if (/req\.session\.destroy|req\.session\.regenerate/.test(line)) return false;
      if (/cookie\s*:\s*\{[^}]*secure\s*:\s*false/i.test(line)) return true;
      return false;
    },
    explanation: "Session configuration lacks proper expiration, secure cookie flags, or session regeneration after authentication, enabling session fixation and hijacking.",
    impact: "Session hijacking, fixation attacks, and persistent unauthorized access after logout.",
    fix: "Set secure cookie flags (httpOnly, secure, sameSite), configure session expiration (maxAge), and regenerate session IDs after login.",
    makeCorrection: (line) => {
      if (/resave/.test(line)) return line.replace(/resave\s*:\s*false/, "resave: false, cookie: { httpOnly: true, secure: true, sameSite: 'strict', maxAge: 3600000 }");
      return line.replace(/secure\s*:\s*false/g, "secure: true /* require HTTPS */");
    },
  },
  {
    name: "Improper Error Handling / Stack Trace Leakage",
    category: "Improper Error Handling",
    severity: "Medium",
    cwe: "CWE-209: Generation of Error Message Containing Sensitive Information",
    owasp: "A05:2021-Security Misconfiguration",
    test: (line) => {
      if (/catch\s*\(\s*\w+\s*\)\s*\{[^}]*res\.(?:send|json|status)\s*\([^)]*(?:err|error|stack|message)/i.test(line)) return true;
      if (/\.(?:catch|on\("error")\s*\([^)]*\)\s*\{[^}]*res\.(?:send|json)\s*\(\s*(?:err|error)/i.test(line)) return true;
      if (/app\.use\s*\(\s*function\s*\(\s*err\s*,\s*req\s*,\s*res\s*,\s*next\s*\)/.test(line) && /res\.(?:send|json|status)\s*\([^)]*(?:err\.|error\.|stack)/i.test(line)) return true;
      if (/DEBUG\s*=\s*(?:True|true|1|["']1["'])/i.test(line)) return true;
      return false;
    },
    explanation: "Error handlers expose internal stack traces, file paths, or exception details in HTTP responses, revealing the application's internal structure.",
    impact: "Information leakage aids attackers in mapping the application, identifying vulnerable dependencies, and crafting targeted exploits.",
    fix: "Return generic error messages to clients; log detailed errors server-side only. Use environment-specific error handling.",
    makeCorrection: (line) => {
      if (/DEBUG/.test(line)) return line.replace(/DEBUG\s*=\s*(?:True|true|1)/, "DEBUG = process.env.DEBUG === 'true'");
      return "// Return generic error to client, log details server-side\nres.status(500).json({ error: 'Internal server error' });\nconsole.error('Detailed error:', err);";
    },
  },
  {
    name: "Sensitive Data Exposure in Response",
    category: "Sensitive Data Exposure",
    severity: "High",
    cwe: "CWE-200: Exposure of Sensitive Information",
    owasp: "A02:2021-Cryptographic Failures",
    test: (line) => {
      if (/res\.(?:json|send)\s*\(\s*(?:.*password|.*secret|.*token|.*apiKey|.*credit.?card|.*ssn|.*private.?key)/i.test(line)) return true;
      if (/(?:password|secret|token|apiKey|api_key|credit.?card|ssn|private.?key)\s*[,}].*\)\s*;?\s*$/.test(line) && /res\.(?:json|send)/.test(line)) return true;
      if (/JSON\.stringify\s*\(\s*(?:user|account|profile|req\.user|req\.session)/.test(line) && !/exclude|omit|pick|filter|without/i.test(line)) return true;
      return false;
    },
    explanation: "Sensitive fields (passwords, tokens, API keys, PII) are included in HTTP responses or serialized without redaction.",
    impact: "Credential exposure, identity theft, financial fraud, and regulatory compliance violations.",
    fix: "Explicitly exclude sensitive fields before sending responses; use DTOs or response serializers; never return raw database objects.",
    makeCorrection: (line) => "// Exclude sensitive fields before sending: const { password, ...safeUser } = user;\nres.json(safeUser); // or use a DTO/serializer",
  },
];

// --------------------------------------------------------------------------
// 3. BLOCK DETECTORS (multi-line constructs)
// --------------------------------------------------------------------------
const BLOCK_RULES = [
  {
    name: "Multi-line SQL Injection (Template Literal)",
    category: "Injection Flaws",
    severity: "Critical",
    cwe: "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
    owasp: "A03:2021-Injection",
    explanation: "A multi-line SQL template literal interpolates user input directly into the query string with ${...}.",
    impact: "Attackers can manipulate query logic to bypass authentication, extract entire databases, modify records, or run admin commands.",
    fix: "Use parameterized queries with placeholders (?) and pass values as query parameters.",
    makeCorrection: (blockText) => {
      const open = blockText.indexOf("`");
      const close = blockText.lastIndexOf("`");
      if (open < 0 || close <= open) return null;
      const prefix = blockText.slice(0, open);
      const suffix = blockText.slice(close + 1);
      const body = blockText.slice(open + 1, close);
      const t = tokenizeTemplate(body);
      const params = t.params.filter((p) => p && p.trim());
      if (!params.length) return null;
      const sql = t.literals.join("?").replace(/\s+/g, " ").trim();
      return [prefix + JSON.stringify(sql) + ", [" + params.join(", ") + "]" + suffix];
    },
    detect(lines) {
      const blocks = [];
      let i = 0;
      const countChar = (s, ch) => { let n = 0; for (const c of s) if (c === ch) n++; return n; };
      while (i < lines.length) {
        const line = lines[i] || "";
        if (line.includes("`") && /(?:select|insert|update|delete|from|where)\b/i.test(line) && line.includes("${")) {
          let unclosed = countChar(line, "`");
          let end = i;
          while (unclosed % 2 === 1 && end < lines.length - 1) {
            end++;
            unclosed += countChar(lines[end], "`");
          }
          if (unclosed % 2 === 0 && end > i && /(?:select|insert|update|delete|from|where)\b/i.test(lines.slice(i, end + 1).join("\n"))) {
            blocks.push({ start: i, end });
            i = end + 1;
            continue;
          }
        }
        i++;
      }
      return blocks;
    },
  },
];

// --------------------------------------------------------------------------
// main scanner
// --------------------------------------------------------------------------
function buildCorrectedCode(lines, lineNum, correctedLine) {
  const before = lines.slice(Math.max(0, lineNum - 2), lineNum - 1);
  const after = lines.slice(lineNum, Math.min(lines.length, lineNum + 1));
  return before.concat([correctedLine]).concat(after).join("\n");
}

function scanCode(code, { entropyEnabled = true } = {}) {
  if (!code || typeof code !== "string") {
    return { totalFindings: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0, findings: [] };
  }

  const lines = code.split("\n");
  const findings = [];

  function addFinding(rule, opts) {
    const {
      lineNum,
      lineEnd = lineNum,
      vulnerableCode,
      correctedCode,
      method,
      confidence,
      matchPreview,
    } = opts;
    findings.push({
      type: rule.name,
      category: rule.category || "Secrets Exposure",
      severity: rule.severity,
      line: lineNum,
      lineEnd,
      vulnerableCode,
      correctedCode,
      cwe: rule.cwe,
      owasp: rule.owasp,
      explanation: rule.explanation,
      impact: rule.impact,
      fix: rule.fix,
      confidence,
      method,
      matchPreview,
    });
  }

  // 1. Secret rules scan the WHOLE code (multiple matches per line allowed).
  for (const rule of SECRET_RULES) {
    rule.regex.lastIndex = 0;
    const matches = [...code.matchAll(rule.regex)];
    for (const m of matches) {
      const lineNum = code.slice(0, m.index).split("\n").length;
      const originalLine = lines[lineNum - 1] || m[0];
      const vulnerableCode = extractCodeSnippet(lines, lineNum, 1);
      const correctedLine = rule.makeCorrection ? rule.makeCorrection(originalLine) : originalLine;
      const correctedCode = buildCorrectedCode(lines, lineNum, correctedLine);
      addFinding(rule, {
        lineNum,
        vulnerableCode,
        correctedCode,
        method: "pattern",
        confidence: 0.95,
        matchPreview: maskSecret(m[0]),
      });
    }
  }

  // 2. Code vulnerability rules scan every line.
  lines.forEach((line, idx) => {
    const lineNum = idx + 1;
    for (const rule of CODE_RULES) {
      if (rule.test(line)) {
        const vulnerableCode = extractCodeSnippet(lines, lineNum, 1);
        const correctedLine = rule.makeCorrection ? rule.makeCorrection(line) : line;
        const correctedCode = buildCorrectedCode(lines, lineNum, correctedLine);
        addFinding(rule, {
          lineNum,
          vulnerableCode,
          correctedCode,
          method: "static",
          confidence: 0.92,
          matchPreview: line.trim().slice(0, 120),
        });
      }
    }
  });

  // 3. Block rules scan multi-line constructs.
  for (const rule of BLOCK_RULES) {
    // only run the block detector if the whole file contains both backticks
    if (!code.includes("`")) continue;
    const blocks = rule.detect(lines);
    for (const blk of blocks) {
      const start = blk.start;
      const end = blk.end;
      const ctxStart = Math.max(0, start - 1);
      const ctxEnd = Math.min(lines.length, end + 1);
      const vulnerableCode = lines.slice(ctxStart, ctxEnd).join("\n");
      const blockText = lines.slice(start, end + 1).join("\n");
      const correctedBlock = rule.makeCorrection ? rule.makeCorrection(blockText) : null;
      let correctedCode = vulnerableCode;
      if (Array.isArray(correctedBlock) && correctedBlock.length) {
        correctedCode = lines.slice(ctxStart, start)
          .concat(correctedBlock)
          .concat(lines.slice(end + 1, ctxEnd))
          .join("\n");
      }
      addFinding(rule, {
        lineNum: start + 1,
        lineEnd: end + 1,
        vulnerableCode,
        correctedCode,
        method: "static",
        confidence: 0.9,
        matchPreview: lines[start].trim().slice(0, 120),
      });
    }
  }

  // 4. Shannon entropy pass on long string literals (if enabled).
  if (entropyEnabled) {
    const stringLiteralRegex = /["']([A-Za-z0-9+/=_\-!@#$%^&*]{24,})["']/g;
    const matches = [...code.matchAll(stringLiteralRegex)];
    for (const m of matches) {
      const candidate = m[1];
      const entropy = shannonEntropy(candidate);
      if (entropy >= 4.2) {
        const lineNum = code.slice(0, m.index).split("\n").length;
        const originalLine = lines[lineNum - 1] || candidate;
        const alreadyFlagged = findings.some((f) => f.line === lineNum && f.category === "Secrets Exposure");
        if (!alreadyFlagged) {
          const vulnerableCode = extractCodeSnippet(lines, lineNum, 1);
          const correctedLine = originalLine.replace(candidate, "process.env.SECRET_TOKEN");
          const correctedCode = buildCorrectedCode(lines, lineNum, correctedLine);
          addFinding({
            name: "High-Entropy Secret String",
            category: "Secrets Exposure",
            severity: entropy >= 4.6 ? "High" : "Medium",
            cwe: "CWE-798: Use of Hard-coded Credentials",
            owasp: "A07:2021-Identification and Authentication Failures",
            explanation: `A high-entropy string (entropy score: ${entropy.toFixed(2)}) was detected. Random high-entropy strings typically represent embedded cryptographic tokens, API keys, or credentials.`,
            impact: "If exposed, this token could allow unauthorized parties to authenticate or bypass security controls.",
            fix: "Move this secret token into an environment variable and load it securely at runtime.",
            confidence: Math.min(0.9, entropy / 5.0),
          }, {
            lineNum,
            vulnerableCode,
            correctedCode,
            method: "entropy",
            confidence: Math.min(0.9, entropy / 5.0),
            matchPreview: maskSecret(candidate),
          });
        }
      }
    }
  }

  // Deduplicate findings by line & type
  const deduped = [];
  const seenKeys = new Set();
  for (const f of findings) {
    const key = `${f.line}-${f.type}`;
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      deduped.push(f);
    }
  }
  deduped.sort((a, b) => a.line - b.line || a.severity.localeCompare(b.severity));

  return {
    totalFindings: deduped.length,
    critical: deduped.filter((f) => f.severity === "Critical").length,
    high: deduped.filter((f) => f.severity === "High").length,
    medium: deduped.filter((f) => f.severity === "Medium").length,
    low: deduped.filter((f) => f.severity === "Low").length,
    info: deduped.filter((f) => f.severity === "Info").length,
    findings: deduped,
  };
}

module.exports = {
  scanCode,
  shannonEntropy,
  maskSecret,
  extractCodeSnippet,
};