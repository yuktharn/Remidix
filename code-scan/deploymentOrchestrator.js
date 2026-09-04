// code-scan/deploymentOrchestrator.js
// Orchestrate deployment to free-tier services (Render, Vercel, Railway)

const https = require('https');

class DeploymentError extends Error {
  constructor(message, service, code) {
    super(message);
    this.name = 'DeploymentError';
    this.service = service;
    this.code = code;
  }
}

async function httpRequest(method, url, headers, body) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const protocol = url.startsWith('https') ? https : require('http');
    
    const options = {
      hostname: urlObj.hostname,
      port: urlObj.port,
      path: urlObj.pathname + urlObj.search,
      method,
      headers,
    };

    const req = protocol.request(options, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data ? JSON.parse(data) : {},
          });
        } catch (e) {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: data,
          });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

class DeploymentOrchestrator {
  constructor(config = {}) {
    this.renderToken = config.RENDER_API_KEY || config.renderToken || process.env.RENDER_API_KEY;
    this.vercelToken = config.VERCEL_TOKEN || config.vercelToken || process.env.VERCEL_TOKEN || process.env.VERCEL_API_TOKEN;
    this.railwayToken = config.RAILWAY_API_KEY || config.railwayToken || process.env.RAILWAY_API_KEY;
    this.githubToken = config.GITHUB_TOKEN || config.githubToken || process.env.GITHUB_TOKEN;
  }

  async deployBackend(projectConfig) {
    const token = projectConfig.apiKey || projectConfig.renderToken || this.renderToken;
    if (!token || token.includes('your_render_api_key')) {
      throw new DeploymentError(
        'Render API key not configured. Please supply your Render API token in deployment settings or configure RENDER_API_KEY in .env (get token at https://dashboard.render.com/u/settings#api-keys).',
        'Render',
        'MISSING_TOKEN'
      );
    }


    try {
      const payload = {
        name: projectConfig.name,
        repo: projectConfig.repoUrl,
        branch: projectConfig.branch || 'main',
        runtime: this.mapRuntime(projectConfig.runtime),
        buildCommand: projectConfig.buildCommand || 'npm install && npm run build',
        startCommand: projectConfig.startCommand || 'npm start',
        envVars: Object.entries(projectConfig.envVars || {}).map(([key, value]) => ({
          key,
          value: String(value),
        })),
        plan: 'free',
      };

      const response = await httpRequest(
        'POST',
        'https://api.render.com/v1/services',
        {
          'Authorization': `Bearer ${this.renderToken}`,
          'Content-Type': 'application/json',
        },
        JSON.stringify(payload)
      );

      if (response.status !== 201) {
        throw new DeploymentError(
          `Render API error: ${response.body.message || response.status}`,
          'Render',
          'API_ERROR'
        );
      }

      return {
        service: 'Render',
        status: 'deployed',
        url: response.body.serviceDetails?.url || `https://${projectConfig.name}.onrender.com`,
        deploymentId: response.body.id,
        logs: 'Check Render dashboard for build logs',
      };
    } catch (err) {
      if (err instanceof DeploymentError) throw err;
      throw new DeploymentError(err.message, 'Render', 'REQUEST_FAILED');
    }
  }

  async deployFrontend(projectConfig) {
    const token = projectConfig.apiKey || projectConfig.vercelToken || this.vercelToken;
    if (!token || token.includes('your_vercel_api_token')) {
      throw new DeploymentError(
        'Vercel API token not configured. Please supply your Vercel token in deployment settings or configure VERCEL_TOKEN in .env (get token at https://vercel.com/account/tokens).',
        'Vercel',
        'MISSING_TOKEN'
      );
    }

    try {
      const payload = {
        name: projectConfig.name,
        git: {
          repo: projectConfig.repoUrl.replace('https://github.com/', '').replace('.git', ''),
          type: 'github',
        },
        buildCommand: projectConfig.buildCommand || 'npm run build',
        outputDirectory: projectConfig.outputDir || 'dist',
        env: projectConfig.envVars || {},
        framework: 'other', // Auto-detect or specify
        regions: ['iad1'], // US East (free tier)
      };

      const response = await httpRequest(
        'POST',
        'https://api.vercel.com/v1/projects',
        {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        JSON.stringify(payload)
      );

      if (response.status !== 201) {
        throw new DeploymentError(
          `Vercel API error: ${response.body.message || response.status}`,
          'Vercel',
          'API_ERROR'
        );
      }

      return {
        service: 'Vercel',
        status: 'deployed',
        url: response.body.domains?.[0] || `https://${projectConfig.name}.vercel.app`,
        projectId: response.body.id,
        logs: 'Check Vercel dashboard for build logs',
      };
    } catch (err) {
      if (err instanceof DeploymentError) throw err;
      throw new DeploymentError(err.message, 'Vercel', 'REQUEST_FAILED');
    }
  }

  async deployDatabase(dbConfig) {
    const service = dbConfig.preferredService || 'Render';

    if (service === 'Render') {
      const token = dbConfig.apiKey || dbConfig.renderToken || this.renderToken;
      if (!token || token.includes('your_render_api_key')) {
        throw new DeploymentError('Render API key not configured for database provisioning.', 'Render', 'MISSING_TOKEN');
      }
      return this.deployDatabaseRender(dbConfig);
    } else if (service === 'Railway') {
      const token = dbConfig.apiKey || dbConfig.railwayToken || this.railwayToken;
      if (!token || token.includes('your_railway_api_key')) {
        throw new DeploymentError('Railway API key not configured for database provisioning.', 'Railway', 'MISSING_TOKEN');
      }
      return this.deployDatabaseRailway(dbConfig);
    }

    throw new DeploymentError(`Unknown DB service: ${service}`, 'Unknown', 'INVALID_SERVICE');
  }


  async deployDatabaseRender(dbConfig) {
    try {
      const payload = {
        name: dbConfig.name || `${dbConfig.type.toLowerCase()}-${Date.now()}`,
        databaseEngine: dbConfig.type.toLowerCase(), // postgres, mysql, mongodb
        version: dbConfig.version || 'latest',
        plan: 'free',
        region: 'oregon',
      };

      const response = await httpRequest(
        'POST',
        'https://api.render.com/v1/databases',
        {
          'Authorization': `Bearer ${this.renderToken}`,
          'Content-Type': 'application/json',
        },
        JSON.stringify(payload)
      );

      if (response.status !== 201) {
        throw new DeploymentError(
          `Failed to create DB: ${response.body.message || response.status}`,
          'Render',
          'API_ERROR'
        );
      }

      return {
        service: 'Render',
        type: dbConfig.type,
        status: 'provisioning',
        connectionString: response.body.connectionString || 'Check Render dashboard',
        host: response.body.host,
        port: response.body.port,
        username: response.body.username,
        databaseName: response.body.name,
      };
    } catch (err) {
      if (err instanceof DeploymentError) throw err;
      throw new DeploymentError(err.message, 'Render', 'REQUEST_FAILED');
    }
  }

  async deployDatabaseRailway(dbConfig) {
    // Railway uses GraphQL, simplified HTTP wrapper
    try {
      const payload = {
        input: {
          environmentId: process.env.RAILWAY_ENV_ID || 'default',
          name: dbConfig.name || `${dbConfig.type.toLowerCase()}-${Date.now()}`,
          template: dbConfig.type.toLowerCase(), // postgres, mysql, mongodb
        },
      };

      const response = await httpRequest(
        'POST',
        'https://api.railway.app/graphql',
        {
          'Authorization': `Bearer ${this.railwayToken}`,
          'Content-Type': 'application/json',
        },
        JSON.stringify(payload)
      );

      return {
        service: 'Railway',
        type: dbConfig.type,
        status: 'provisioning',
        connectionString: response.body.connectionString || 'Check Railway dashboard',
      };
    } catch (err) {
      throw new DeploymentError(err.message, 'Railway', 'REQUEST_FAILED');
    }
  }

  mapRuntime(runtime) {
    const map = {
      'Node.js': 'node',
      'Python': 'python',
      'Go': 'go',
      'Ruby': 'ruby',
      'Java': 'java',
    };
    return map[runtime] || 'node';
  }

  async getDeploymentStatus(deploymentId, service) {
    /**
     * Check deployment status
     */
    if (service === 'Render') {
      const response = await httpRequest(
        'GET',
        `https://api.render.com/v1/services/${deploymentId}`,
        {
          'Authorization': `Bearer ${this.renderToken}`,
        }
      );
      return {
        service,
        status: response.body.status,
        url: response.body.serviceDetails?.url,
        updatedAt: response.body.updatedAt,
      };
    } else if (service === 'Vercel') {
      const response = await httpRequest(
        'GET',
        `https://api.vercel.com/v1/projects/${deploymentId}`,
        {
          'Authorization': `Bearer ${this.vercelToken}`,
        }
      );
      return {
        service,
        status: response.body.latestDeployment?.state,
        url: `https://${response.body.domains?.[0]}`,
        updatedAt: response.body.latestDeployment?.createdAt,
      };
    }
    throw new DeploymentError('Unknown service', service, 'INVALID_SERVICE');
  }
}

module.exports = { DeploymentOrchestrator, DeploymentError };
