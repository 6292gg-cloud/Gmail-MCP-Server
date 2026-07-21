import http, { createServer, type Server } from 'node:http';
import https from 'node:https';
import { promises as dns } from 'node:dns';
import type { AddressInfo } from 'node:net';
import type { gmail_v1 } from 'googleapis';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { getToolByName, InspectDraftSchema } from './tools.js';
import {
  inspectDraft,
  inspectDraftPayload,
  probeRemoteAsset,
} from './draft-inspection.js';

interface FixtureOptions {
  text?: string;
  html?: string;
  attachments?: string[];
  zeroByte?: boolean;
}

interface RecordedRequest {
  method: string;
  path: string;
  range?: string;
}

interface RecordedConnection {
  hostname: string;
  hostHeader: string;
  servername?: string;
}

const PUBLIC_HOST = '93.184.216.34';
let server: Server;
let publicBase: string;
let port: number;
let requests: RecordedRequest[] = [];
let connections: RecordedConnection[] = [];
const nativeHttpRequest = http.request.bind(http);

function encoded(value: string): string {
  return Buffer.from(value).toString('base64url');
}

function fixture(options: FixtureOptions = {}): gmail_v1.Schema$Draft {
  const text = options.text ?? 'One\n\nTwo';
  const html = options.html ?? '<p>One</p><p>Two</p>';
  const attachmentParts = (options.attachments ?? []).map((filename, index) => ({
    filename,
    mimeType: filename.endsWith('.pdf') ? 'application/pdf' : 'application/octet-stream',
    body: {
      attachmentId: `attachment-${index}`,
      size: options.zeroByte && index === 0 ? 0 : 12,
    },
  }));

  return {
    id: 'draft-1',
    message: {
      id: 'message-1',
      threadId: 'thread-1',
      payload: {
        mimeType: 'multipart/mixed',
        headers: [
          { name: 'From', value: 'Sender <sender@example.com>' },
          { name: 'To', value: 'recipient@example.com' },
          { name: 'Cc', value: 'copy@example.com' },
          { name: 'Bcc', value: '' },
          { name: 'Subject', value: 'Inspection' },
        ],
        parts: [
          {
            mimeType: 'multipart/alternative',
            parts: [
              { mimeType: 'text/plain', body: { data: encoded(text), size: text.length } },
              {
                mimeType: 'multipart/related',
                parts: [
                  { mimeType: 'text/html', body: { data: encoded(html), size: html.length } },
                ],
              },
            ],
          },
          ...attachmentParts,
        ],
      },
    },
  };
}

function signatureWithAsset(url: string): string {
  return `<table data-wisestamp="1"><tr><td>Trevi Signature</td><td><img src="${url}"></td></tr></table>`;
}

beforeAll(async () => {
  server = createServer((request, response) => {
    const requestUrl = new URL(request.url ?? '/', 'http://fixture.invalid');
    requests.push({
      method: request.method ?? '',
      path: requestUrl.pathname,
      range: request.headers.range,
    });

    const redirect = (location: string) => {
      response.writeHead(302, { location });
      response.end();
    };

    switch (requestUrl.pathname) {
      case '/ok':
        response.writeHead(200, { 'content-type': 'image/png' });
        response.end(request.method === 'HEAD' ? undefined : 'not retained');
        return;
      case '/query-required':
        response.writeHead(requestUrl.searchParams.get('token') === 'required-secret' ? 200 : 403);
        response.end();
        return;
      case '/redirect-one':
        redirect(`${publicBase}/ok?token=redirect-secret#fragment`);
        return;
      case '/redirect-a':
        redirect(`${publicBase}/redirect-b`);
        return;
      case '/redirect-b':
        redirect(`${publicBase}/redirect-c`);
        return;
      case '/redirect-c':
        redirect(`${publicBase}/ok`);
        return;
      case '/head-405':
        if (request.method === 'HEAD') {
          response.writeHead(405);
          response.end();
        } else {
          response.writeHead(206, { 'content-type': 'image/png' });
          response.end('secret-response-body');
        }
        return;
      case '/head-405-redirect':
        if (request.method === 'HEAD') {
          response.writeHead(405);
          response.end();
        } else {
          redirect(`${publicBase}/ok`);
        }
        return;
      case '/head-405-redirect-second-fallback':
        if (request.method === 'HEAD') {
          response.writeHead(405);
          response.end();
        } else {
          redirect(`${publicBase}/head-405`);
        }
        return;
      case '/missing':
        response.writeHead(404);
        response.end('missing-body');
        return;
      case '/deadline':
        setTimeout(() => {
          if (request.method === 'HEAD') {
            response.writeHead(405);
            response.end();
          } else {
            response.writeHead(206);
            response.end('too late');
          }
        }, request.method === 'HEAD' ? 25 : 250);
        return;
      case '/to-loopback':
        redirect(`http://127.0.0.1:${port}/private`);
        return;
      case '/to-metadata':
        redirect('http://169.254.169.254/latest/meta-data');
        return;
      case '/to-localhost':
        redirect(`http://localhost:${port}/private`);
        return;
      default:
        response.writeHead(500);
        response.end();
    }
  });

  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  port = (server.address() as AddressInfo).port;
  publicBase = `http://${PUBLIC_HOST}:${port}`;

  vi.spyOn(http, 'request').mockImplementation(((options: http.RequestOptions, callback: (response: http.IncomingMessage) => void) => {
    const headers = options.headers as Record<string, string> | undefined;
    connections.push({
      hostname: String(options.hostname ?? options.host ?? ''),
      hostHeader: String(headers?.Host ?? headers?.host ?? ''),
      servername: options.servername,
    });
    return nativeHttpRequest({ ...options, hostname: '127.0.0.1' }, callback);
  }) as typeof http.request);
  vi.spyOn(https, 'request').mockImplementation(((options: https.RequestOptions, callback: (response: http.IncomingMessage) => void) => {
    const headers = options.headers as Record<string, string> | undefined;
    connections.push({
      hostname: String(options.hostname ?? options.host ?? ''),
      hostHeader: String(headers?.Host ?? headers?.host ?? ''),
      servername: options.servername,
    });
    return nativeHttpRequest({ ...options, protocol: 'http:', hostname: '127.0.0.1', servername: undefined }, callback);
  }) as typeof https.request);

  vi.stubGlobal('fetch', vi.fn(() => { throw new Error('probe transport must not call fetch'); }));
});

beforeEach(() => {
  requests = [];
  connections = [];
});

afterAll(async () => {
  vi.unstubAllGlobals();
  await new Promise<void>((resolve, reject) => {
    server.close(error => error ? reject(error) : resolve());
  });
});

describe('draft payload inspection', () => {
  it('fails a multi-paragraph message whose HTML collapsed into one block', () => {
    const result = inspectDraftPayload(
      fixture({ text: 'One\n\nTwo', html: '<div>One Two</div>' }),
      { requireHtml: true },
    );

    expect(result.verdict).toBe('NOT_READY');
    expect(result.body).toMatchObject({ hasText: true, hasHtml: true, textParagraphs: 2, htmlBlocks: 1 });
    expect(result.errors).toContain('HTML body does not preserve the plain-text paragraph structure');
  });

  it('passes structured HTML with one matching signature and exact attachments', () => {
    const signatureHtml = '<table data-wisestamp="1"><tr><td>Sig</td></tr></table>';
    const result = inspectDraftPayload(
      fixture({
        text: 'One\n\nTwo',
        html: `<p>One</p><p>Two</p>${signatureHtml}`,
        attachments: ['report.pdf'],
      }),
      { requireHtml: true, requireSignature: true, expectedAttachments: ['report.pdf'] },
      signatureHtml,
    );

    expect(result.verdict).toBe('READY');
    expect(result.headers).toEqual({
      from: 'Sender <sender@example.com>',
      to: 'recipient@example.com',
      cc: 'copy@example.com',
      bcc: '',
      subject: 'Inspection',
      threadId: 'thread-1',
    });
    expect(result.signature.matches).toBe(1);
    expect(result.attachments).toEqual([{
      filename: 'report.pdf',
      mimeType: 'application/pdf',
      size: 12,
      attachmentId: 'attachment-0',
    }]);
  });

  it('rejects wrong recipients and subject without echoing private header values', () => {
    const actualRecipient = 'actual-private@example.com';
    const expectedRecipient = 'expected-private@example.com';
    const draft = fixture();
    const headers = draft.message?.payload?.headers ?? [];
    const to = headers.find(header => header.name === 'To');
    const subject = headers.find(header => header.name === 'Subject');
    if (to) to.value = actualRecipient;
    if (subject) subject.value = 'Actual private subject';

    const result = inspectDraftPayload(draft, {
      expectedHeaders: {
        to: [expectedRecipient],
        subject: 'Expected private subject',
      },
    });

    expect(result.verdict).toBe('NOT_READY');
    expect(result.errors).toContain('Draft To header does not match expected value');
    expect(result.errors).toContain('Draft Subject header does not match expected value');
    const diagnostics = result.errors.join(' ');
    expect(diagnostics).not.toContain(actualRecipient);
    expect(diagnostics).not.toContain(expectedRecipient);
    expect(diagnostics).not.toContain('private subject');
    expect(Math.max(...result.errors.map(error => error.length))).toBeLessThan(100);
  });

  it('rejects wrong plain and HTML bodies without leaking complete content', () => {
    const actualText = 'actual-private-body';
    const expectedText = 'expected-private-body';
    const actualHtml = '<p>actual-private-html</p>';
    const expectedHtml = '<p>expected-private-html</p>';

    const result = inspectDraftPayload(
      fixture({ text: actualText, html: actualHtml }),
      { expectedBody: expectedText, expectedHtmlBody: expectedHtml },
    );

    expect(result.verdict).toBe('NOT_READY');
    expect(result.errors).toContain('Draft plain-text body does not match expected content');
    expect(result.errors).toContain('Draft HTML body does not match expected content');
    const diagnostics = result.errors.join(' ');
    expect(diagnostics).not.toContain(actualText);
    expect(diagnostics).not.toContain(expectedText);
    expect(diagnostics).not.toContain(actualHtml);
    expect(diagnostics).not.toContain(expectedHtml);
  });

  it('matches canonical line endings and excludes the signature plus applySignature separator from HTML', () => {
    const signatureHtml = '<table data-wisestamp="1"><tr><td>Trevi Signature</td></tr></table>';
    const reserializedSignature = '<table class="gmail_signature"><tbody><tr><td>Trevi\n Signature</td></tr></tbody></table>';
    const signedDraft = fixture({
      text: 'One\n\nTwo',
      html: `<p>One</p>\n<p>Two</p><br><br>${reserializedSignature}`,
    });
    const subject = signedDraft.message?.payload?.headers?.find(header => header.name === 'Subject');
    if (subject) subject.value = 'Inspection\r\n continued';
    const result = inspectDraftPayload(
      signedDraft,
      {
        expectedHeaders: {
          from: 'Sender <sender@example.com>',
          to: ['recipient@example.com'],
          cc: ['copy@example.com'],
          bcc: [],
          subject: 'Inspection\n continued',
        },
        expectedBody: 'One\r\n\r\nTwo',
        expectedHtmlBody: '<p>One</p>\r\n<p>Two</p>',
        requireHtml: true,
        requireSignature: true,
        checkRemoteSignatureAssets: false,
      },
      signatureHtml,
    );

    expect(result.signature.matches).toBe(1);
    expect(result.verdict).toBe('READY');
  });

  it('does not let a reserialized signature table hide a collapsed message body', () => {
    const signatureHtml = '<table data-wisestamp="1"><tr><td><a href="https://cdn.example.com/card?source=mail">Trevi Signature</a></td></tr></table>';
    const reserialized = '<table class="gmail_signature"><tbody><tr><td><a href="https://cdn.example.com/card#footer"> Trevi\n Signature </a></td></tr></tbody></table>';
    const result = inspectDraftPayload(
      fixture({ text: 'One\n\nTwo', html: `<div>One Two</div>${reserialized}` }),
      { requireHtml: true, requireSignature: true },
      signatureHtml,
    );

    expect(result.signature.matches).toBe(1);
    expect(result.body).toMatchObject({ textParagraphs: 2, htmlBlocks: 1 });
    expect(result.errors).toContain('HTML body does not preserve the plain-text paragraph structure');
    expect(result.verdict).toBe('NOT_READY');
  });

  it('does not count a partially sliced signature container as a message block', () => {
    const signatureHtml = '<table data-wisestamp="1"><tr><td>Signature Boundary Token</td></tr></table>';
    const result = inspectDraftPayload(
      fixture({ text: 'One\n\nTwo', html: `<p>One Two</p>${signatureHtml}` }),
      { requireHtml: true, requireSignature: true },
      signatureHtml,
    );

    expect(result.signature.matches).toBe(1);
    expect(result.body.htmlBlocks).toBe(1);
    expect(result.verdict).toBe('NOT_READY');
  });

  it('excludes a complete decorative signature table before the first visible token', () => {
    const signatureHtml = '<table aria-hidden="true"><tr><td></td></tr></table><table data-wisestamp="1"><tr><td>Visible Signature Token</td></tr></table>';
    const result = inspectDraftPayload(
      fixture({ text: 'One\n\nTwo', html: `<p>One Two</p>${signatureHtml}` }),
      { requireHtml: true, requireSignature: true },
      signatureHtml,
    );

    expect(result.signature.matches).toBe(1);
    expect(result.body.htmlBlocks).toBe(1);
    expect(result.verdict).toBe('NOT_READY');
  });

  it('counts a multi-row body table as one block', () => {
    const result = inspectDraftPayload(
      fixture({ text: 'One\n\nTwo', html: '<table><tr><td>One</td></tr><tr><td>Two</td></tr></table>' }),
      { requireHtml: true },
    );

    expect(result.body.htmlBlocks).toBe(1);
    expect(result.verdict).toBe('NOT_READY');
  });

  it.each([
    '<p>One</p><p>Two</p>',
    '<div>One<br><br>Two</div>',
    '<p>One</p><ul><li>Two A</li><li>Two B</li></ul>',
  ])('accepts body-level formatting containers: %s', html => {
    expect(inspectDraftPayload(fixture({ html }), { requireHtml: true }).verdict).toBe('READY');
  });

  it('forces NOT_READY when a signature fingerprint matches twice', () => {
    const signatureHtml = '<table data-wisestamp="1"><tr><td>Unique Signature Text</td></tr></table>';
    const result = inspectDraftPayload(
      fixture({ html: `<p>One</p><p>Two</p>${signatureHtml}${signatureHtml}` }),
      { requireSignature: true },
      signatureHtml,
    );

    expect(result.signature.matches).toBe(2);
    expect(result.errors).toContain('Signature fingerprint appears more than once');
    expect(result.verdict).toBe('NOT_READY');
  });

  it('detects duplicate asset-only signature fingerprints', () => {
    const signatureHtml = '<table><tr><td><img src="https://assets.example.com/logo.png?variant=mail"></td></tr></table>';
    const result = inspectDraftPayload(
      fixture({ html: `<p>One</p><p>Two</p>${signatureHtml}${signatureHtml}` }),
      { requireSignature: true },
      signatureHtml,
    );

    expect(result.signature.matches).toBe(2);
    expect(result.verdict).toBe('NOT_READY');
  });

  it('rejects a missing required signature and an invalid asset-check option', () => {
    const missing = inspectDraftPayload(fixture(), { requireSignature: true }, '<p>Missing Signature</p>');
    const invalid = inspectDraftPayload(fixture(), { checkRemoteSignatureAssets: true });

    expect(missing.signature.matches).toBe(0);
    expect(missing.verdict).toBe('NOT_READY');
    expect(invalid.errors).toContain('Remote signature assets cannot be checked when a signature is not required');
    expect(invalid.verdict).toBe('NOT_READY');
  });

  it('fails missing, zero-byte, and unexpected attachments', () => {
    const result = inspectDraftPayload(
      fixture({ attachments: ['wrong.pdf'], zeroByte: true }),
      { expectedAttachments: ['report.pdf'] },
    );

    expect(result.verdict).toBe('NOT_READY');
    expect(result.errors.join(' ')).toMatch(/missing.*report\.pdf/i);
    expect(result.errors.join(' ')).toMatch(/zero-byte/i);
    expect(result.errors.join(' ')).toMatch(/unexpected.*wrong\.pdf/i);
  });

  it('compares attachment basenames case-sensitively', () => {
    const basename = inspectDraftPayload(
      fixture({ attachments: ['folder/report.pdf'] }),
      { expectedAttachments: ['report.pdf'] },
    );
    const wrongCase = inspectDraftPayload(
      fixture({ attachments: ['Report.pdf'] }),
      { expectedAttachments: ['report.pdf'] },
    );

    expect(basename.verdict).toBe('READY');
    expect(wrongCase.verdict).toBe('NOT_READY');
  });

  it('accepts a nonzero attachment when no exact attachment set was requested', () => {
    const result = inspectDraftPayload(fixture({ attachments: ['informational.pdf'] }), {});

    expect(result.verdict).toBe('READY');
    expect(result.attachments).toHaveLength(1);
  });

  it('bounds previews and signature assets without retaining message bodies', () => {
    const assets = Array.from({ length: 25 }, (_, index) => `<img src="https://assets.example.com/${index}.png?secret=${index}">`).join('');
    const signatureHtml = `<table><tr><td>Bounded Signature ${assets}</td></tr></table>`;
    const secretBody = `message-secret-${'x'.repeat(700)}`;
    const result = inspectDraftPayload(
      fixture({ text: secretBody, html: `<p>${secretBody}</p>${signatureHtml}` }),
      { requireSignature: true },
      signatureHtml,
    );
    const serialized = JSON.stringify(result);

    expect(result.body.preview.length).toBeLessThanOrEqual(500);
    expect(result.signature.assets.length).toBeLessThanOrEqual(20);
    expect(serialized).not.toContain('secret=24');
    expect(result.errors).toContain('Signature contains more than 20 remote assets');
  });

  it('counts image elements separately from deduplicated probe URLs', () => {
    const signatureHtml = '<table><tr><td>Repeated Image Signature<img src="https://assets.example.com/logo.png"><img src="https://assets.example.com/logo.png"></td></tr></table>';
    const result = inspectDraftPayload(
      fixture({ html: `<p>One</p><p>Two</p>${signatureHtml}` }),
      { requireSignature: true, checkRemoteSignatureAssets: false },
      signatureHtml,
    );

    expect(result.signature.images).toBe(2);
    expect(result.signature.assets).toHaveLength(1);
  });
});

describe('bounded remote asset probing', () => {
  it('accepts 200 and follows one validated public redirect', async () => {
    const direct = await probeRemoteAsset(`${publicBase}/ok?token=direct-secret#fragment`);
    const redirected = await probeRemoteAsset(`${publicBase}/redirect-one?token=first-secret`);

    expect(direct).toEqual({ url: `${publicBase}/ok`, status: 'reachable', httpStatus: 200 });
    expect(redirected).toEqual({ url: `${publicBase}/ok`, status: 'reachable', httpStatus: 200 });
    expect(requests.map(request => request.path)).toEqual(['/ok', '/redirect-one', '/ok']);
    expect(JSON.stringify([direct, redirected])).not.toMatch(/direct-secret|first-secret|redirect-secret|fragment/);
  });

  it('marks a third redirect unreachable and stops following', async () => {
    const result = await probeRemoteAsset(`${publicBase}/redirect-a`);

    expect(result).toMatchObject({ status: 'unreachable', httpStatus: 302 });
    expect(requests.map(request => request.path)).toEqual(['/redirect-a', '/redirect-b', '/redirect-c']);
  });

  it('falls back once from HEAD 405 to a body-cancelled range GET', async () => {
    const result = await probeRemoteAsset(`${publicBase}/head-405?token=get-secret`);

    expect(result).toEqual({ url: `${publicBase}/head-405`, status: 'reachable', httpStatus: 206 });
    expect(requests).toEqual([
      { method: 'HEAD', path: '/head-405', range: undefined },
      { method: 'GET', path: '/head-405', range: 'bytes=0-0' },
    ]);
    expect(JSON.stringify(result)).not.toMatch(/secret-response-body|get-secret/);
  });

  it('pins the connection to the validated public IP without a second resolver lookup', async () => {
    const lookup = vi.spyOn(dns, 'lookup')
      .mockResolvedValueOnce([{ address: PUBLIC_HOST, family: 4 }])
      .mockResolvedValueOnce([{ address: '127.0.0.1', family: 4 }]);
    try {
      const result = await probeRemoteAsset(`http://asset.test:${port}/ok`);

      expect(result).toMatchObject({ status: 'reachable', httpStatus: 200 });
      expect(lookup).toHaveBeenCalledTimes(1);
      expect(connections).toEqual([{
        hostname: PUBLIC_HOST,
        hostHeader: `asset.test:${port}`,
        servername: undefined,
      }]);
    } finally {
      lookup.mockRestore();
    }
  });

  it('preserves the original hostname as TLS SNI on a pinned HTTPS connection', async () => {
    const lookup = vi.spyOn(dns, 'lookup').mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }]);
    try {
      const result = await probeRemoteAsset(`https://secure.test:${port}/ok`);

      expect(result).toMatchObject({ status: 'reachable', httpStatus: 200 });
      expect(connections).toEqual([{
        hostname: PUBLIC_HOST,
        hostHeader: `secure.test:${port}`,
        servername: 'secure.test',
      }]);
    } finally {
      lookup.mockRestore();
    }
  });

  it('resolves, validates, and pins again before the range GET', async () => {
    const lookup = vi.spyOn(dns, 'lookup').mockResolvedValue([{ address: PUBLIC_HOST, family: 4 }]);
    try {
      const result = await probeRemoteAsset(`http://asset.test:${port}/head-405`);

      expect(result).toMatchObject({ status: 'reachable', httpStatus: 206 });
      expect(lookup).toHaveBeenCalledTimes(2);
      expect(connections.map(connection => connection.hostname)).toEqual([PUBLIC_HOST, PUBLIC_HOST]);
    } finally {
      lookup.mockRestore();
    }
  });

  it('routes a range-GET redirect through the validated redirect pipeline', async () => {
    const result = await probeRemoteAsset(`${publicBase}/head-405-redirect`);

    expect(result).toEqual({ url: `${publicBase}/ok`, status: 'reachable', httpStatus: 200 });
    expect(requests).toEqual([
      { method: 'HEAD', path: '/head-405-redirect', range: undefined },
      { method: 'GET', path: '/head-405-redirect', range: 'bytes=0-0' },
      { method: 'HEAD', path: '/ok', range: undefined },
    ]);
  });

  it('allows only one range-GET fallback across a redirect chain', async () => {
    const result = await probeRemoteAsset(`${publicBase}/head-405-redirect-second-fallback`);

    expect(result).toMatchObject({ status: 'unreachable', httpStatus: 405 });
    expect(requests).toEqual([
      { method: 'HEAD', path: '/head-405-redirect-second-fallback', range: undefined },
      { method: 'GET', path: '/head-405-redirect-second-fallback', range: 'bytes=0-0' },
      { method: 'HEAD', path: '/head-405', range: undefined },
    ]);
  });

  it('treats a terminal 404 and unsupported URL as failures', async () => {
    await expect(probeRemoteAsset(`${publicBase}/missing`)).resolves.toMatchObject({
      status: 'unreachable',
      httpStatus: 404,
    });
    await expect(probeRemoteAsset('data:image/png;base64,c2VjcmV0')).resolves.toMatchObject({
      url: 'data:',
      status: 'unsupported',
    });
  });

  it('uses one deadline across HEAD and the range-GET fallback', async () => {
    const startedAt = Date.now();
    const result = await probeRemoteAsset(`${publicBase}/deadline`, 120);

    expect(result).toMatchObject({ status: 'unreachable', reason: 'Request timed out' });
    expect(requests.map(request => request.method)).toEqual(['HEAD', 'GET']);
    expect(Date.now() - startedAt).toBeLessThan(220);
  });

  it.each([
    ['/to-loopback', '127.0.0.1'],
    ['/to-metadata', '169.254.169.254'],
    ['/to-localhost', 'localhost'],
  ])('rejects a redirect from a public fixture to private target %s', async (path, target) => {
    const result = await probeRemoteAsset(`${publicBase}${path}`);

    expect(result).toMatchObject({ status: 'unreachable' });
    expect(result.reason).toContain(target);
    expect(requests).toHaveLength(1);
  });

  it.each([
    'http://user:pass@93.184.216.34/image.png',
    'http://0.1.2.3/image.png',
    'http://10.0.0.1/image.png',
    'http://100.64.0.1/image.png',
    'http://127.0.0.1/image.png',
    'http://169.254.169.254/image.png',
    'http://192.168.1.1/image.png',
    'http://[::1]/image.png',
    'http://[fc00::1]/image.png',
    'http://[fe80::1]/image.png',
    'http://[::ffff:127.0.0.1]/image.png',
  ])('rejects credentials and non-public address before fetch: %s', async url => {
    const result = await probeRemoteAsset(url);

    expect(result.status).toBe('unreachable');
    expect(requests).toHaveLength(0);
  });
});

describe('asynchronous draft inspection', () => {
  it('returns READY when the required signature asset is reachable', async () => {
    const signatureHtml = signatureWithAsset(`${publicBase}/ok?token=signature-secret`);
    const result = await inspectDraft(
      fixture({ html: `<p>One</p><p>Two</p>${signatureHtml}` }),
      { requireHtml: true, requireSignature: true },
      signatureHtml,
    );

    expect(result.verdict).toBe('READY');
    expect(result.signature.images).toBe(1);
    expect(result.signature.assets).toEqual([{
      url: `${publicBase}/ok`,
      status: 'reachable',
      httpStatus: 200,
    }]);
  });

  it('probes the original signed asset URL but retains only its redacted form', async () => {
    const signatureHtml = signatureWithAsset(`${publicBase}/query-required?token=required-secret#private-fragment`);
    const result = await inspectDraft(
      fixture({ html: `<p>One</p><p>Two</p>${signatureHtml}` }),
      { requireSignature: true },
      signatureHtml,
    );

    expect(result.verdict).toBe('READY');
    expect(result.signature.assets[0]).toEqual({
      url: `${publicBase}/query-required`,
      status: 'reachable',
      httpStatus: 200,
    });
    expect(JSON.stringify(result)).not.toMatch(/required-secret|private-fragment/);
  });

  it('rejects and probes a changed draft signature image instead of the template image', async () => {
    const templateSignature = signatureWithAsset(`${publicBase}/ok?source=template`);
    const draftSignature = signatureWithAsset(`${publicBase}/missing?source=draft`);
    const result = await inspectDraft(
      fixture({ html: `<p>One</p><p>Two</p>${draftSignature}` }),
      { requireSignature: true },
      templateSignature,
    );

    expect(result.verdict).toBe('NOT_READY');
    expect(result.errors).toContain('Draft signature assets do not match the expected signature assets');
    expect(result.signature.assets).toEqual([{
      url: `${publicBase}/missing`,
      status: 'unreachable',
      httpStatus: 404,
      reason: 'HTTP 404',
    }]);
    expect(requests.map(request => request.path)).toEqual(['/missing']);
  });

  it.each([
    ['/missing', 'unreachable'],
    ['data:image/png;base64,c2VjcmV0', 'unsupported'],
  ])('returns NOT_READY when a required signature asset is %s', async (asset, expectedStatus) => {
    const assetUrl = asset.startsWith('/') ? `${publicBase}${asset}` : asset;
    const signatureHtml = signatureWithAsset(assetUrl);
    const result = await inspectDraft(
      fixture({ html: `<p>One</p><p>Two</p>${signatureHtml}` }),
      { requireSignature: true },
      signatureHtml,
    );

    expect(result.signature.assets[0]?.status).toBe(expectedStatus);
    expect(result.verdict).toBe('NOT_READY');
  });
});

describe('inspect_draft MCP wiring', () => {
  it('defaults asset checking to requireSignature and rejects inconsistent options', () => {
    expect(InspectDraftSchema.parse({ draftId: 'r-1', requireSignature: true })).toMatchObject({
      draftId: 'r-1',
      requireSignature: true,
      checkRemoteSignatureAssets: true,
    });
    expect(InspectDraftSchema.parse({ draftId: 'r-1' })).toMatchObject({
      draftId: 'r-1',
      requireSignature: false,
      requireHtml: false,
      checkRemoteSignatureAssets: false,
    });
    expect(() => InspectDraftSchema.parse({
      draftId: 'r-1',
      requireSignature: false,
      checkRemoteSignatureAssets: true,
    })).toThrow();
  });

  it('registers inspect_draft as read-only for readonly and modify scopes', () => {
    const tool = getToolByName('inspect_draft');

    expect(tool?.annotations.readOnlyHint).toBe(true);
    expect(tool?.scopes).toEqual(['gmail.readonly', 'gmail.modify']);
  });

  it('retains expected headers and complete text/HTML bodies in parsed handler options', () => {
    expect(InspectDraftSchema.parse({
      draftId: 'r-1',
      expectedHeaders: {
        from: 'Sender <sender@example.com>',
        to: ['recipient@example.com'],
        cc: ['copy@example.com'],
        bcc: [],
        subject: 'Subject',
      },
      expectedBody: 'Plain body',
      expectedHtmlBody: '<p>Plain body</p>',
    })).toMatchObject({
      expectedHeaders: {
        from: 'Sender <sender@example.com>',
        to: ['recipient@example.com'],
        cc: ['copy@example.com'],
        bcc: [],
        subject: 'Subject',
      },
      expectedBody: 'Plain body',
      expectedHtmlBody: '<p>Plain body</p>',
    });
  });

});
