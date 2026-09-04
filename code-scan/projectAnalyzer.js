// code-scan/projectAnalyzer.js
// Detect project type, tech stack, and deployment recommendations
// Based on file structure and configuration files

function analyzeProjectType(filesContent) {
  /**
   * @param {Object} filesContent - key: filename, value: file content
   * @returns {Object} detection results
   */
  
  const analysis = {
    frontend: { detected: false, framework: null, buildTool: null },
    backend: { detected: false, framework: null, runtime: null },
    database: { detected: false, type: null },
    languages: [],
    buildScripts: {},
    envVars: [],
    recommendedDeployment: {},
    projectStructure: {
      hasMonorepo: false,
      isSPA: false,
      isSSR: false,
      isFullStack: false,
      isAPIOnly: false,
    },
  };

  // Files to check
  const fileNames = Object.keys(filesContent);
  const fileContent = (name) => filesContent[name] || '';

  // 1. Detect Frontend
  if (fileNames.includes('package.json') || fileNames.includes('frontend/package.json')) {
    const pkgJson = filesContent['package.json'] || filesContent['frontend/package.json'];
    try {
      const pkg = JSON.parse(pkgJson);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps.react) {
        analysis.frontend.detected = true;
        analysis.frontend.framework = 'React';
        if (deps['next']) analysis.projectStructure.isSSR = true;
        else analysis.projectStructure.isSPA = true;
        analysis.frontend.buildTool = deps.vite ? 'Vite' : deps['react-scripts'] ? 'CRA' : 'webpack';
      }
      if (deps.vue) {
        analysis.frontend.detected = true;
        analysis.frontend.framework = 'Vue';
        analysis.projectStructure.isSPA = true;
      }
      if (deps.svelte) {
        analysis.frontend.detected = true;
        analysis.frontend.framework = 'Svelte';
        analysis.projectStructure.isSPA = true;
      }
      if (deps['@angular/core']) {
        analysis.frontend.detected = true;
        analysis.frontend.framework = 'Angular';
        analysis.projectStructure.isSPA = true;
      }
      if (deps.next) {
        analysis.frontend.detected = true;
        analysis.frontend.framework = 'Next.js';
        analysis.backend.detected = true;
        analysis.backend.runtime = 'Node.js';
        analysis.projectStructure.isSSR = true;
        analysis.projectStructure.isFullStack = true;
      }
      if (deps.nuxt) {
        analysis.frontend.detected = true;
        analysis.frontend.framework = 'Nuxt';
        analysis.projectStructure.isSSR = true;
      }

      // Build scripts
      if (pkg.scripts) {
        analysis.buildScripts = pkg.scripts;
      }
    } catch (e) {
      console.error('Failed to parse package.json:', e.message);
    }
  }

  // 2. Detect Backend
  if (fileNames.includes('package.json')) {
    const pkgJson = fileContent('package.json');
    try {
      const pkg = JSON.parse(pkgJson);
      const deps = { ...pkg.dependencies, ...pkg.devDependencies };

      if (deps.express || deps.fastify || deps.koa || deps.hapi) {
        analysis.backend.detected = true;
        analysis.backend.runtime = 'Node.js';
        if (deps.express) analysis.backend.framework = 'Express';
        else if (deps.fastify) analysis.backend.framework = 'Fastify';
        else if (deps.koa) analysis.backend.framework = 'Koa';
        else if (deps.hapi) analysis.backend.framework = 'Hapi';
      }

      // Check for monorepo
      if (pkg.workspaces) {
        analysis.projectStructure.hasMonorepo = true;
      }
    } catch (e) {
      console.error('Failed to parse package.json:', e.message);
    }
  }

  // 3. Detect Python Backend
  if (fileNames.some((f) => f.endsWith('requirements.txt') || f.endsWith('Pipfile'))) {
    analysis.backend.detected = true;
    analysis.backend.runtime = 'Python';

    const reqsTxt = fileContent('requirements.txt');
    const pipfile = fileContent('Pipfile');
    const allDeps = reqsTxt + pipfile;

    if (allDeps.includes('django')) analysis.backend.framework = 'Django';
    else if (allDeps.includes('flask')) analysis.backend.framework = 'Flask';
    else if (allDeps.includes('fastapi')) analysis.backend.framework = 'FastAPI';
    else if (allDeps.includes('fastapi')) analysis.backend.framework = 'FastAPI';
    else if (allDeps.includes('pyramid')) analysis.backend.framework = 'Pyramid';
  }

  // 4. Detect Go Backend
  if (fileNames.includes('go.mod') || fileNames.includes('go.sum')) {
    analysis.backend.detected = true;
    analysis.backend.runtime = 'Go';

    const goMod = fileContent('go.mod');
    if (goMod.includes('github.com/gin-gonic/gin')) analysis.backend.framework = 'Gin';
    else if (goMod.includes('github.com/labstack/echo')) analysis.backend.framework = 'Echo';
    else if (goMod.includes('github.com/gorilla/mux')) analysis.backend.framework = 'Gorilla Mux';
  }

  // 5. Detect Database
  const allContent = Object.values(filesContent).join('\n');

  if (fileNames.some((f) => f.includes('docker-compose')) && allContent.includes('postgres')) {
    analysis.database.detected = true;
    analysis.database.type = 'PostgreSQL';
  }
  if (allContent.includes('mysql') || allContent.includes('MySQL')) {
    analysis.database.detected = true;
    analysis.database.type = 'MySQL';
  }
  if (fileNames.includes('.mongorc') || allContent.includes('mongodb') || allContent.includes('mongoose')) {
    analysis.database.detected = true;
    analysis.database.type = 'MongoDB';
  }
  if (allContent.includes('redis') && fileNames.some((f) => f.includes('docker-compose'))) {
    analysis.database.type = analysis.database.type ? `${analysis.database.type} + Redis` : 'Redis';
  }

  // Detect environment variables
  const envExampleFile = filesContent['.env.example'] || filesContent['.env.sample'] || '';
  if (envExampleFile) {
    const lines = envExampleFile.split('\n');
    analysis.envVars = lines
      .filter((l) => l.trim() && !l.trim().startsWith('#') && l.includes('='))
      .map((l) => l.split('=')[0].trim());
  }

  // 6. Determine deployment strategy
  if (analysis.frontend.detected && analysis.backend.detected) {
    analysis.projectStructure.isFullStack = true;
    analysis.recommendedDeployment = {
      frontend: 'Vercel',
      backend: analysis.backend.runtime === 'Node.js' ? 'Render' : analysis.backend.runtime === 'Python' ? 'Render' : 'Render',
      database: analysis.database.type ? 'Managed (Railway/Render)' : 'None',
      estimatedCost: '$0-50/month (free tier eligible)',
    };
  } else if (analysis.frontend.detected) {
    analysis.projectStructure.isSPA = true;
    analysis.recommendedDeployment = {
      frontend: 'Vercel',
      database: 'None',
      estimatedCost: '$0 (free tier)',
    };
  } else if (analysis.backend.detected) {
    analysis.projectStructure.isAPIOnly = true;
    analysis.recommendedDeployment = {
      backend: analysis.backend.runtime === 'Node.js' ? 'Render' : analysis.backend.runtime === 'Python' ? 'Render' : 'Render',
      database: analysis.database.type ? 'Managed (Railway/Render)' : 'None',
      estimatedCost: '$0-30/month (free tier eligible)',
    };
  }

  // 7. Detect languages
  const langMap = {
    '.js': 'JavaScript',
    '.jsx': 'React JSX',
    '.ts': 'TypeScript',
    '.tsx': 'React TSX',
    '.py': 'Python',
    '.java': 'Java',
    '.go': 'Go',
    '.rb': 'Ruby',
    '.rs': 'Rust',
    '.php': 'PHP',
    '.cs': 'C#',
    '.cpp': 'C++',
    '.c': 'C',
  };

  for (const fileName of fileNames) {
    for (const [ext, lang] of Object.entries(langMap)) {
      if (fileName.endsWith(ext) && !analysis.languages.includes(lang)) {
        analysis.languages.push(lang);
      }
    }
  }

  return analysis;
}

function recommendDeploymentSequence(analysis) {
  /**
   * Returns optimal deployment order
   */
  const sequence = [];

  if (analysis.projectStructure.isFullStack) {
    sequence.push('database');
    sequence.push('backend');
    sequence.push('frontend');
  } else if (analysis.projectStructure.isAPIOnly) {
    if (analysis.database.detected) sequence.push('database');
    sequence.push('backend');
  } else if (analysis.projectStructure.isSPA) {
    sequence.push('frontend');
  }

  return sequence;
}

module.exports = { analyzeProjectType, recommendDeploymentSequence };
