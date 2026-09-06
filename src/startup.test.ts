import { execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, describe, expect, it } from 'vitest';

const entry = fileURLToPath(new URL('../dist/index.js', import.meta.url));
const fixtures: string[] = [];
const oauth = { installed: { client_id: 'fixture-client', client_secret: 'fixture-secret' } };

beforeAll(() => {
  // Test the current source, never a leftover dist build from another revision.
  execFileSync(process.execPath, ['node_modules/typescript/bin/tsc'], {
    cwd: fileURLToPath(new URL('..', import.meta.url)), windowsHide: true, stdio: 'pipe',
  });
}, 60_000);

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-startup-test-'));
  fixtures.push(directory);
  const oauthPath = path.join(directory, 'selected-oauth.json');
  const credentialsPath = path.join(directory, 'selected-credentials.json');
  fs.writeFileSync(oauthPath, JSON.stringify(oauth));
  fs.writeFileSync(credentialsPath, JSON.stringify({ refresh_token: 'fixture-refresh' }));
  return { directory, oauthPath, credentialsPath };
}

afterEach(() => {
  for (const directory of fixtures.splice(0)) {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

async function initialize(files: ReturnType<typeof fixture>, options: { auth?: boolean; defaultOAuth?: boolean } = {}) {
  return new Promise<{ stdout: string; stderr: string; response?: any; code: number | null }>((resolve, reject) => {
    const child = spawn(process.execPath, [entry, ...(options.auth ? ['auth', '--scopes=invalid-fixture-scope'] : ['--tool-prefix=fixture_'])], {
      cwd: files.directory,
      env: {
        ...process.env,
        GMAIL_OAUTH_PATH: options.defaultOAuth ? undefined : files.oauthPath,
        GMAIL_CREDENTIALS_PATH: files.credentialsPath,
        GMAIL_ACCOUNT_EMAIL: 'fixture@example.test',
        GMAIL_ACCOUNT_LABEL: 'Startup test fixture',
        ...(options.defaultOAuth ? { HOME: files.directory, USERPROFILE: files.directory } : {}),
      },
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let response: any;
    const timer = setTimeout(() => { child.kill(); reject(new Error('Fixture startup timed out')); }, 15_000);
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString();
      for (const line of stdout.split('\n')) {
        try {
          const message = JSON.parse(line);
          if (message.id === 1) { response = message; child.kill(); }
        } catch { /* Keep non-JSON stdout so the regression assertion can detect it. */ }
      }
    });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.once('error', (error) => { clearTimeout(timer); reject(error); });
    child.once('close', (code) => { clearTimeout(timer); resolve({ stdout, stderr, response, code }); });
    child.stdin.on('error', () => { /* A rejected configuration may close stdin immediately. */ });
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {
      protocolVersion: '2024-11-05', capabilities: {}, clientInfo: { name: 'startup-regression', version: '1' },
    } }) + '\n');
  });
}

describe('built Gmail server startup', () => {
  it('keeps explicitly selected OAuth keys unchanged when cwd contains different keys', async () => {
    const files = fixture();
    const original = fs.readFileSync(files.oauthPath, 'utf8');
    fs.writeFileSync(path.join(files.directory, 'gcp-oauth.keys.json'), JSON.stringify({ installed: {
      client_id: 'unselected-client', client_secret: 'unselected-secret',
    } }));
    const result = await initialize(files);
    expect(result.response?.result).toBeDefined();
    expect(fs.readFileSync(files.oauthPath, 'utf8')).toBe(original);
    expect(result.stdout.trim().split('\n').every((line) => {
      try { return JSON.parse(line).jsonrpc === '2.0'; } catch { return false; }
    })).toBe(true);
  }, 20_000);

  it('rejects missing credentials before advertising a healthy server', async () => {
    const files = fixture();
    fs.unlinkSync(files.credentialsPath);
    const result = await initialize(files);
    expect(result.response).toBeUndefined();
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('GMAIL_CREDENTIALS_MISSING');
    expect(result.stdout).toBe('');
  }, 20_000);

  it('rejects an unusable token object without exposing its contents', async () => {
    const files = fixture();
    fs.writeFileSync(files.credentialsPath, JSON.stringify({ access_token: 123, secret_marker: 'fixture-private-value' }));
    const result = await initialize(files);
    expect(result.response).toBeUndefined();
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('GMAIL_CREDENTIALS_INVALID');
    expect(result.stderr).not.toContain('fixture-private-value');
  }, 20_000);

  it('reports malformed credential JSON without echoing credential contents', async () => {
    const files = fixture();
    fs.writeFileSync(files.credentialsPath, '{"refresh_token":"fixture-private-value", BROKEN}');
    const result = await initialize(files);
    expect(result.response).toBeUndefined();
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('GMAIL_CREDENTIALS_INVALID');
    expect(result.stderr).not.toContain('fixture-private-value');
  }, 20_000);

  it('allows explicit authentication setup before a credentials file exists', async () => {
    const files = fixture();
    fs.unlinkSync(files.credentialsPath);
    const result = await initialize(files, { auth: true });
    // An invalid scope stops before opening a browser or making network requests,
    // and proves auth reached argument validation after loading the OAuth client.
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('Invalid scope(s): invalid-fixture-scope');
    expect(result.stderr).not.toContain('GMAIL_CREDENTIALS_MISSING');
    expect(fs.existsSync(files.credentialsPath)).toBe(false);
  }, 20_000);

  it('bootstraps missing default OAuth keys only during explicit authentication', async () => {
    const files = fixture();
    const localOAuth = path.join(files.directory, 'gcp-oauth.keys.json');
    const defaultOAuth = path.join(files.directory, '.gmail-mcp', 'gcp-oauth.keys.json');
    fs.writeFileSync(localOAuth, JSON.stringify(oauth));
    const serving = await initialize(files, { defaultOAuth: true });
    expect(serving.stderr).toContain('GMAIL_OAUTH_MISSING');
    expect(fs.existsSync(defaultOAuth)).toBe(false);
    const auth = await initialize(files, { auth: true, defaultOAuth: true });
    expect(auth.stderr).toContain('Invalid scope(s): invalid-fixture-scope');
    expect(fs.readFileSync(defaultOAuth, 'utf8')).toBe(fs.readFileSync(localOAuth, 'utf8'));
  }, 20_000);
});
