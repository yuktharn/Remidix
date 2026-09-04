// llmAnalyzer.js
// Semantic vulnerability analysis and secure code remediation using Groq LLM.
// Analyzes the exact submitted code, detects real security weaknesses,
// provides human-level explanations, security impact, CWE/OWASP references,
// and generates the exact corrected code fixing the vulnerability.

require("dotenv").config();

const GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions";
// Models available on this Groq account (fastest first)
const PRIMARY_MODEL = "qwen/qwen3.8-27b";
const FALLBACK_MODELS = ["openai/gpt-oss-20b", "groq/compound-mini", "allam-2-7b"];

const SYSTEM_PROMPT = `You are a Principal Application Security Engineer and Senior Code Reviewer.
Analyze the EXACT code provided by the user and detect REAL security vulnerabilities.

Categories of interest:
- Secrets Exposure (hardcoded API keys, secrets, tokens, passwords, private keys, database credentials)
- Injection Flaws (SQL injection, command injection, XSS, NoSQL injection, template injection, path traversal)
- Insecure Authentication & Session Management (hardcoded admin credentials, broken auth, weak password hashing, weak tokens)
- Broken Access Control (missing authorization, IDOR, privilege escalation)
- Security Misconfigurations (debug mode enabled, permissive CORS, disabled TLS verification, dangerous eval/exec)
- Information Disclosure (sensitive data in logs, raw error stack trace leakage in API responses)
- Cryptographic Failures (MD5/SHA1 for passwords, weak ciphers, hardcoded IVs)

CRITICAL INSTRUCTIONS:
1. Base all findings strictly on the EXACT code provided. Do not fabricate or invent fake line numbers or unrelated issues.
2. For EVERY finding, extract the exact lines of "vulnerableCode" from the submitted code and generate the exact "correctedCode" derived from that exact code, fixing the vulnerability while preserving original functionality.
3. Provide comprehensive, human-level explanations for "explanation" (What is the problem?), "impact" (Why is it risky?), and "fix" (How to fix?).
4. Provide the exact 1-indexed line number in the submitted code.
5. Provide relevant CWE (e.g., "CWE-89: SQL Injection", "CWE-798: Use of Hard-coded Credentials") and OWASP Top 10 references.
6. Provide "fullCorrectedCode" containing the entire submitted source code rewritten securely with all vulnerabilities fixed.

Return ONLY a single valid JSON object with this exact schema:
{
  "fullCorrectedCode": "<complete submitted code rewritten securely>",
  "findings": [
    {
      "type": "<Specific vulnerability name, e.g. SQL Injection>",
      "category": "Secrets Exposure" | "Injection Flaws" | "Insecure Authentication" | "Security Misconfigurations" | "Information Disclosure" | "Broken Access Control" | "Best Practice Issues",
      "severity": "Critical" | "High" | "Medium" | "Low" | "Info",
      "line": <integer line number in submitted code, e.g. 7>,
      "lineEnd": <integer end line number, e.g. 7>,
      "vulnerableCode": "<exact line(s) from submitted code>",
      "correctedCode": "<exact corrected replacement line(s)>",
      "explanation": "<Plain-English explanation of what is wrong in the code>",
      "impact": "<Detailed explanation of what an attacker could achieve and security consequences>",
      "fix": "<Clear, step-by-step developer guide on how to fix and safeguard the code>",
      "cwe": "<e.g. CWE-89: SQL Injection>",
      "owasp": "<e.g. A03:2021-Injection>",
      "confidence": <float between 0.8 and 1.0>
    }
  ]
}
Do not include markdown fences outside the JSON. Return only the JSON object.`;

async function callGroqAPI(model, prompt) {
  const response = await fetch(GROQ_API_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${process.env.GROQ_API_KEY}`,
    },
    body: JSON.stringify({
      model: model,
      temperature: 0.1,
      max_tokens: 3500,
      messages: [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: prompt },
      ],
    }),
  });

  if (!response.ok) {
    const errText = await response.text();
    throw new Error(`Groq API error (${response.status}): ${errText}`);
  }

  const data = await response.json();
  const rawText = data.choices?.[0]?.message?.content?.trim() || "";

  // Strip possible markdown code blocks if returned
  const cleaned = rawText
    .replace(/^```json\s*/i, "")
    .replace(/^```\s*/i, "")
    .replace(/```\s*$/i, "")
    .trim();

  return JSON.parse(cleaned);
}

async function analyzeWithLLM(code, { fileName = "source_code" } = {}) {
  if (!process.env.GROQ_API_KEY) {
    console.warn("GROQ_API_KEY not configured — skipping LLM semantic analysis");
    return { findings: [], fullCorrectedCode: null };
  }

  if (!code || !code.trim()) {
    return { findings: [], fullCorrectedCode: null };
  }

  // Cap code at 150 lines to stay within Groq token limits and keep analysis fast
  const MAX_LINES = 150;
  const codeLines = code.split("\n");
  const truncated = codeLines.length > MAX_LINES;
  const codeToAnalyze = truncated
    ? codeLines.slice(0, MAX_LINES).join("\n") + `\n// ... (${codeLines.length - MAX_LINES} more lines truncated for analysis)`
    : code;

  // Prepend line numbers so the LLM has exact 1-to-1 line reference
  const numberedLines = codeToAnalyze
    .split("\n")
    .map((line, idx) => `${idx + 1}: ${line}`)
    .join("\n");

  const userPrompt = `File Name: ${fileName}

Source Code (with line numbers for reference):
\`\`\`
${numberedLines}
\`\`\`

Analyze the code above and return the JSON findings and full corrected code as specified.`;

  const modelsToTry = [PRIMARY_MODEL, ...FALLBACK_MODELS];

  for (const model of modelsToTry) {
    try {
      const result = await callGroqAPI(model, userPrompt);
      if (result && Array.isArray(result.findings)) {
        const validatedFindings = result.findings.map((item) => ({
          type: item.type || "Security Vulnerability",
          category: item.category || "Injection Flaws",
          severity: ["Critical", "High", "Medium", "Low", "Info"].includes(item.severity)
            ? item.severity
            : "Medium",
          line: Number.isInteger(item.line) && item.line > 0 ? item.line : 1,
          lineEnd: Number.isInteger(item.lineEnd) && item.lineEnd >= (item.line || 1) ? item.lineEnd : (item.line || 1),
          vulnerableCode: item.vulnerableCode || "",
          correctedCode: item.correctedCode || "",
          explanation: item.explanation || "Vulnerability detected in source code.",
          impact: item.impact || "May allow unauthorized actions or data compromise.",
          fix: item.fix || "Apply secure coding practices to remediate this issue.",
          cwe: item.cwe || "CWE-Other",
          owasp: item.owasp || "OWASP Top 10",
          confidence: typeof item.confidence === "number" ? Math.max(0.1, Math.min(1.0, item.confidence)) : 0.9,
          method: "llm",
          matchPreview: item.vulnerableCode ? item.vulnerableCode.slice(0, 80) : item.type,
        }));

        return {
          findings: validatedFindings,
          fullCorrectedCode: result.fullCorrectedCode || null,
        };
      }
    } catch (err) {
      console.warn(`Model ${model} failed: ${err.message}. Trying next model...`);
    }
  }

  return { findings: [], fullCorrectedCode: null };
}

module.exports = { analyzeWithLLM };