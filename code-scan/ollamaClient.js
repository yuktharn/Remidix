// ollamaClient.js
// Calls Ollama directly for vulnerability explanation, secure fix generation,
// and secret detection. Consolidates the Python AI engine into Node.js.

require("dotenv").config();

const OLLAMA_API_URL = process.env.OLLAMA_API_URL || "http://localhost:11434";
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || "llama2-uncensored";

// ─── Ollama caller ───────────────────────────────────────────────────
async function callOllama(prompt, { maxTokens = 1000, temperature = 0.7 } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000); // 5s — fail fast, fall back to Groq

  // qwen3 defaults to "thinking" mode — prepend /no_think to get direct output
  const finalPrompt = `/no_think\n${prompt}`;

  try {
    const res = await fetch(`${OLLAMA_API_URL}/api/generate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        model: OLLAMA_MODEL,
        prompt: finalPrompt,
        stream: false,
        temperature,
        top_p: 0.9,
        options: { num_predict: maxTokens },
      }),
    });

    if (!res.ok) {
      const text = await res.text().catch(() => "");
      throw new Error(`Ollama API error ${res.status}: ${text.slice(0, 200)}`);
    }

    const data = await res.json();
    // qwen3 and similar models may put output in "thinking" field; use response, fall back to thinking
    return data.response || data.thinking || "";
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error("Ollama request timed out after 8s");
    }
    if (err.cause?.code === "ECONNREFUSED" || err.message?.includes("fetch failed")) {
      throw new Error(
        `Ollama server not reachable at ${OLLAMA_API_URL}. Make sure Ollama is running.`
      );
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }
}

// ─── POST /ai/explain ────────────────────────────────────────────────
async function explainVulnerability({ code, vulnerability_type, language, file_name }) {
  const prompt = `You are a security expert. Analyze this ${language} code vulnerability and provide:
1. A clear explanation of WHY this is vulnerable
2. The potential IMPACT if exploited
3. A brief remediation tip

Code:
\`\`\`${(language || "").toLowerCase()}
${code}
\`\`\`

Vulnerability Type: ${vulnerability_type}

Format your response as JSON with keys: "explanation", "impact", "severity" (Critical/High/Medium/Low), "remediation"`;

  const raw = await callOllama(prompt);

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    data = {
      explanation: raw,
      impact: "Potential security risk",
      severity: "High",
      remediation: "Review and fix according to security guidelines",
    };
  }

  return {
    vulnerability_type: vulnerability_type || "AUTO_ANALYSIS",
    explanation: data.explanation || "",
    impact: data.impact || "",
    severity: data.severity || "High",
    remediation: data.remediation || "",
  };
}

// ─── POST /ai/generate-fix ───────────────────────────────────────────
async function generateFix({ code, vulnerability_type, language, file_name }) {
  const prompt = `You are a security expert. Fix this ${language} code vulnerability while maintaining functionality.

Original Code:
\`\`\`${(language || "").toLowerCase()}
${code}
\`\`\`

Vulnerability: ${vulnerability_type}

Requirements:
- Fix MUST be syntactically correct ${language} code
- Maintain original functionality
- Use security best practices
- Add explanatory comments

Respond with JSON containing:
- "fixed_code": The corrected code (without markdown)
- "explanation": Brief explanation of changes
- "changes": List of specific changes made
- "confidence": Confidence level (0-1) that this fix is correct`;

  const raw = await callOllama(prompt, { maxTokens: 2000, temperature: 0.3 });

  let data;
  try {
    data = JSON.parse(raw);
  } catch {
    data = {
      fixed_code: code,
      explanation: "Unable to generate fix automatically. Please review manually.",
      changes: [],
      confidence: 0.3,
    };
  }

  return {
    original_code: code,
    fixed_code: data.fixed_code || "",
    explanation: data.explanation || "",
    changes: Array.isArray(data.changes) ? data.changes : [],
    confidence: Math.min(1.0, Math.max(0.0, Number(data.confidence) || 0.5)),
  };
}

// ─── POST /ai/detect-secrets ─────────────────────────────────────────
// Pure regex — no Ollama needed. Matches the Python engine's patterns exactly.
const SECRET_PATTERNS = {
  AWS_KEY: /AKIA[0-9A-Z]{16}/gi,
  GITHUB_TOKEN: /ghp_[A-Za-z0-9_]{36,255}/gi,
  STRIPE_KEY: /sk_live_[0-9a-zA-Z]{24,}/gi,
  API_KEY: /api[_-]?key['"]?\s*[:=]\s*['"]([^'"]{20,})['"]/gi,
  DATABASE_URL: /(postgres|mysql|mongodb):\/\/[a-zA-Z0-9:@.\/\-]+/gi,
  JWT_SECRET: /jwt[_-]?secret['"]?\s*[:=]\s*['"]([^'"]{20,})['"]/gi,
  PRIVATE_KEY: /-----BEGIN (RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY/gi,
};

function detectSecrets({ code }) {
  if (!code || typeof code !== "string") {
    return { secrets: [], has_secrets: false };
  }

  const secrets = [];

  for (const [secretType, pattern] of Object.entries(SECRET_PATTERNS)) {
    // Reset lastIndex for global patterns
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(code)) !== null) {
      const lineNum = code.slice(0, match.index).split("\n").length;
      const raw = match[0];
      secrets.push({
        type: secretType,
        line: lineNum,
        match: raw.length > 50 ? raw.slice(0, 50) + "..." : raw,
      });
    }
  }

  return { secrets, has_secrets: secrets.length > 0 };
}

// ─── POST /ai/health ─────────────────────────────────────────────────
async function healthCheck() {
  try {
    const res = await fetch(`${OLLAMA_API_URL}/api/tags`, { signal: AbortSignal.timeout(5000) });
    if (res.ok) {
      const data = await res.json();
      const models = (data.models || []).map((m) => m.name);
      return {
        status: "ok",
        ollama: "connected",
        model: OLLAMA_MODEL,
        available_models: models,
      };
    }
    return { status: "ok", ollama: "error", model: OLLAMA_MODEL, error: `HTTP ${res.status}` };
  } catch (err) {
    return { status: "degraded", ollama: "disconnected", model: OLLAMA_MODEL, error: err.message };
  }
}

module.exports = {
  callOllama,
  explainVulnerability,
  generateFix,
  detectSecrets,
  healthCheck,
  OLLAMA_API_URL,
  OLLAMA_MODEL,
};
