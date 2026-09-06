import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { afterEach, describe, expect, it } from 'vitest';

const entry = fileURLToPath(new URL('../dist/index.js', import.meta.url));
const opened: Array<{ client: Client; directory: string }> = [];

async function connect(email?: string) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'gmail-account-server-'));
  const oauthPath = path.join(directory, 'oauth.json');
  const credentialsPath = path.join(directory, 'credentials.json');
  fs.writeFileSync(oauthPath, JSON.stringify({ installed: { client_id: 'fixture', client_secret: 'fixture' } }));
  fs.writeFileSync(credentialsPath, JSON.stringify({ tokens: { access_token: 'fixture', expiry_date: Date.now() + 3_600_000 }, scopes: ['gmail.readonly'] }));
  const env = Object.fromEntries(Object.entries(process.env).filter((pair): pair is [string, string] => pair[1] !== undefined));
  delete env.GMAIL_ACCOUNT_EMAIL;
  if (email) env.GMAIL_ACCOUNT_EMAIL = email;
  Object.assign(env, {
    GMAIL_OAUTH_PATH: oauthPath,
    GMAIL_CREDENTIALS_PATH: credentialsPath,
    GMAIL_ACCOUNT_LABEL: 'Read-only routing fixture',
    HTTPS_PROXY: 'http://127.0.0.1:1',
  });
  const client = new Client({ name: 'account-regression', version: '1' });
  opened.push({ client, directory });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: [entry, '--tool-prefix=fixture_'], cwd: directory, env, stderr: 'pipe' }));
  return client;
}

afterEach(async () => {
  for (const { client, directory } of opened.splice(0)) {
    await client.close();
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

describe('built Gmail account boundary (run npm run build before this suite)', () => {
  it('initializes and lists account-specific tools offline with read-only scope filtering intact', async () => {
    const client = await connect('fixture@example.test');
    const { tools } = await client.listTools();
    const context = tools.find(tool => tool.name === 'fixture_get_account_context');
    expect(context).toBeDefined();
    expect(context?.annotations?.readOnlyHint).toBe(true);
    expect(tools.every(tool => tool.description?.includes('Configured mailbox: fixture@example.test'))).toBe(true);
    expect(tools.some(tool => tool.name === 'fixture_send_email')).toBe(false);
    expect(tools.find(tool => tool.name === 'fixture_search_emails')?.inputSchema.required).toEqual(['query']);
  }, 15_000);

  it.each(['search_emails', 'personal_search_emails'])('rejects unadvertised tool name %s before any account API call', async name => {
    const client = await connect('fixture@example.test');
    const result = await client.callTool({ name, arguments: { query: 'fixture' } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain('exact tool name advertised');
  }, 15_000);

  it('blocks a correctly prefixed business call when expected identity is absent', async () => {
    const client = await connect();
    const result = await client.callTool({ name: 'fixture_search_emails', arguments: { query: 'fixture' } });
    expect(result.isError).toBe(true);
    expect(JSON.stringify(result.content)).toContain('Set GMAIL_ACCOUNT_EMAIL');
  }, 15_000);
});
