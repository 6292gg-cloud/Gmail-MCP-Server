/**
 * HTTP entry point. The stdio entry point gives every Claude/Codex session its own
 * copy of this server - and with one server per Gmail account, that multiplied fast.
 * This one runs once per account and serves every session over loopback.
 *
 * One process still means ONE account: `oauth2Client` and `authorizedScopes` are
 * module scope. They are assigned once at startup and only read afterwards, which
 * is what makes sharing them across sessions safe. Do not make either mutable.
 *
 * ===========================================================================
 * GATE - READ BEFORE POINTING THIS AT A SEND-CAPABLE ACCOUNT
 *
 * If a client disconnects mid-call, res 'close' closes the transport, which
 * aborts the handler's AbortSignal. The tool still RUNS TO COMPLETION and its
 * result is discarded silently. The client sees a transport error, so a model
 * may retry - and the mail has already gone out. That is a duplicate send to a
 * real recipient.
 *
 * Honouring extra.signal is necessary but NOT sufficient: Gmail can accept a
 * send and only then lose the response, and nothing undoes an operation the
 * remote side already accepted. Before serving an account that can send or
 * delete, all three must hold:
 *   1. handlers check extra.signal before starting the effect;
 *   2. operations carry a stable client-supplied id;
 *   3. the server suppresses duplicates by that id and reports uncertain
 *      outcomes as uncertain rather than as a failure that invites a retry.
 *
 * As of 2026-09-22 none of the three hold. Only accounts launched with
 * --scopes=gmail.readonly may be served over HTTP.
 * ===========================================================================
 */
import http from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer as createMcpServer, initRuntime } from './index.js';

const HOST = '127.0.0.1';
const PORT = Number(process.env.GMAIL_MCP_PORT || 0);
const TOKEN = process.env.GMAIL_MCP_TOKEN;
const LABEL = process.env.GMAIL_ACCOUNT_LABEL || process.env.GMAIL_MCP_TOOL_PREFIX || 'gmail';
// One authenticated caller could otherwise OOM the process every session shares.
const MAX_BODY_BYTES = 1_000_000;

if (!TOKEN) {
  process.stderr.write('[gmail:http] refusing to start: GMAIL_MCP_TOKEN is not set\n');
  process.exit(1);
}
if (!PORT) {
  process.stderr.write('[gmail:http] refusing to start: GMAIL_MCP_PORT is not set\n');
  process.exit(1);
}

/** Constant-time compare so the token cannot be recovered by timing the 401. */
function tokenOk(header: string | undefined): boolean {
  if (!header?.startsWith('Bearer ')) return false;
  const given = Buffer.from(header.slice(7));
  const want = Buffer.from(TOKEN!);
  // Length check is required: timingSafeEqual throws on unequal lengths.
  return given.length === want.length && timingSafeEqual(given, want);
}

function sendJson(res: http.ServerResponse, status: number, payload: unknown): void {
  if (res.headersSent) return;
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(payload));
}

class BodyTooLarge extends Error {}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    // Collect bytes and decode ONCE. Appending each Buffer to a string decodes
    // chunks independently, so a multibyte character split across a chunk
    // boundary is silently replaced - and for mail that is message content.
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      // Pause rather than destroy: destroying kills the socket before the 413
      // can flush, so the caller sees a reset instead of an answer.
      if (size > MAX_BODY_BYTES) { req.pause(); reject(new BodyTooLarge()); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

async function start() {
  // Auth and the Gmail client are built once, before we accept anything: a server
  // that accepted connections it could not serve would hang sessions instead of
  // failing here where the supervisor can see it.
  const runtime = await initRuntime();

  const httpServer = http.createServer(async (req, res) => {
    if (req.url === '/health' && req.method === 'GET') {
      sendJson(res, 200, { ok: true, server: 'gmail', account: LABEL, pid: process.pid });
      return;
    }

    // Auth runs BEFORE the body is read, so an unauthenticated caller can never
    // make us buffer anything.
    if (!tokenOk(req.headers.authorization)) {
      sendJson(res, 401, { error: 'unauthorized' });
      return;
    }

    let parsed: unknown;
    try {
      const body = await readBody(req);
      parsed = body ? JSON.parse(body) : undefined;
    } catch (err) {
      if (err instanceof BodyTooLarge) {
        res.on('finish', () => req.destroy());
        sendJson(res, 413, { error: 'payload too large' });
        return;
      }
      if (err instanceof SyntaxError) {
        // This parse happens outside the SDK, so without this a malformed body
        // would surface as a bare HTTP 500.
        sendJson(res, 400, { jsonrpc: '2.0', error: { code: -32700, message: 'Parse error' }, id: null });
        return;
      }
      return; // client aborted mid-body; nothing to answer
    }

    try {
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
        enableDnsRebindingProtection: true,
        allowedHosts: [`${HOST}:${PORT}`, `localhost:${PORT}`],
      });

      const server = createMcpServer(runtime);
      res.on('close', () => { void transport.close(); void server.close(); });

      await server.connect(transport);
      await transport.handleRequest(req, res, parsed);
    } catch (err) {
      process.stderr.write(`[gmail:http] ${String(err)}\n`);
      sendJson(res, 500, { error: 'internal' });
    }
  });

  // Without this an EADDRINUSE arrives as an unhandled 'error' event and kills the
  // process with no explanation - which under a supervisor becomes a restart loop.
  httpServer.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      process.stderr.write(`[gmail:http] port ${PORT} already in use - another instance is running\n`);
    } else {
      process.stderr.write(`[gmail:http] server error: ${String(err)}\n`);
    }
    process.exit(1);
  });

  httpServer.listen(PORT, HOST, () => {
    process.stderr.write(`[gmail:http] ${LABEL} listening on http://${HOST}:${PORT} (pid ${process.pid})\n`);
  });
}

start().catch(err => {
  process.stderr.write(`[gmail:http] startup failed: ${String(err)}\n`);
  process.exit(1);
});
