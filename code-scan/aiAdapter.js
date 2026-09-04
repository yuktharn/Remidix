require('dotenv').config();

// aiAdapter: Uses local Ollama client (Node.js) for AI analysis.
// Falls back to Groq LLM if Ollama is unavailable.

const ollamaClient = require('./ollamaClient');
const llmAnalyzer = require('./llmAnalyzer');

async function analyzeWithLLM(code, opts = {}) {
  const fileName = opts.fileName || 'source_code';
  const language = (fileName.split('.').pop() || 'unknown');
  const startTime = Date.now();

  // Try Ollama first — run explain + fix in PARALLEL for speed
  if (code && code.trim()) {
    try {
      const ollamaOpts = {
        code,
        vulnerability_type: 'AUTO_ANALYSIS',
        language,
        file_name: fileName,
      };

      const [explainResult, fixResult] = await Promise.allSettled([
        ollamaClient.explainVulnerability(ollamaOpts),
        ollamaClient.generateFix(ollamaOpts),
      ]);

      const explainData = explainResult.status === 'fulfilled' ? explainResult.value : null;
      const fixData = fixResult.status === 'fulfilled' ? fixResult.value : null;

      if (explainData || fixData) {
        console.log(`aiAdapter: Ollama analysis completed in ${Date.now() - startTime}ms`);
        const finding = {
          type: 'AI:AutoAnalysis',
          category: 'AI-Driven Analysis',
          severity: explainData?.severity || 'Medium',
          line: 1,
          lineEnd: 1,
          vulnerableCode: (code || '').split('\n').slice(0, 3).join('\n'),
          correctedCode: fixData?.fixed_code || '',
          explanation: explainData?.explanation || explainData?.remediation || 'AI explanation provided',
          impact: explainData?.impact || 'Potential impact described by AI',
          fix: fixData?.explanation || explainData?.remediation || 'Review suggested fix',
          cwe: explainData?.cwe || null,
          owasp: explainData?.owasp || null,
          confidence: typeof fixData?.confidence === 'number' ? fixData.confidence : 0.6,
          method: 'ollama',
          matchPreview: (code || '').slice(0, 120),
          fileName,
        };

        return { findings: [finding], fullCorrectedCode: fixData?.fixed_code || null };
      }
    } catch (err) {
      console.warn('aiAdapter: Ollama AI failed, falling back to Groq:', err.message);
    }
  }

  // Fallback to existing Groq LLM analyzer
  if (llmAnalyzer && typeof llmAnalyzer.analyzeWithLLM === 'function') {
    const result = await llmAnalyzer.analyzeWithLLM(code, opts);
    console.log(`aiAdapter: Groq analysis completed in ${Date.now() - startTime}ms`);
    return result;
  }

  return { findings: [], fullCorrectedCode: null };
}

module.exports = { analyzeWithLLM };
