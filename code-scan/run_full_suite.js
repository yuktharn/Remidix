// run_full_suite.js
// Start backend server, run all integration tests, and cleanly exit

const { spawn } = require('child_process');
const http = require('http');

async function waitForServer(port, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await new Promise((resolve, reject) => {
        const req = http.get(`http://localhost:${port}/history`, (res) => {
          resolve(res.statusCode);
        });
        req.on('error', reject);
        req.end();
      });
      return true;
    } catch {
      await new Promise(r => setTimeout(r, 500));
    }
  }
  throw new Error(`Server failed to start on port ${port} within ${timeoutMs}ms`);
}

async function main() {
  console.log('1. Starting SecureCode Express server...');
  const server = spawn('node', ['index.js'], {
    cwd: __dirname,
    stdio: 'pipe',
    env: process.env,
  });

  server.stdout.on('data', d => process.stdout.write('[server] ' + d.toString()));
  server.stderr.on('data', d => process.stderr.write('[server-err] ' + d.toString()));

  try {
    await waitForServer(4000);
    console.log('2. Server is ready on port 4000. Running tests...\n');

    // Run test_e2e_pipeline
    const testProcess = spawn('node', ['test_e2e_pipeline.js'], {
      cwd: __dirname,
      stdio: 'inherit',
    });

    const exitCode = await new Promise((resolve) => {
      testProcess.on('close', resolve);
    });

    if (exitCode !== 0) {
      console.error(`E2E tests failed with exit code ${exitCode}`);
      process.exit(exitCode);
    }
  } finally {
    console.log('\n3. Shutting down test server...');
    server.kill('SIGTERM');
  }
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
