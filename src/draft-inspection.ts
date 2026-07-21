import { promises as dns } from 'node:dns';
import { isIP } from 'node:net';
import type { gmail_v1 } from 'googleapis';
import { containsSignature, fingerprintSignature, type SignatureFingerprint } from './signature.js';

const MAX_PREVIEW_LENGTH = 500;
const MAX_REMOTE_ASSETS = 20;
const DEFAULT_PROBE_TIMEOUT_MS = 3000;
const MAX_REDIRECTS = 2;

export interface InspectDraftOptions {
  expectedAttachments?: string[];
  requireSignature?: boolean;
  requireHtml?: boolean;
  checkRemoteSignatureAssets?: boolean;
}

export interface DraftInspection {
  verdict: 'READY' | 'NOT_READY';
  errors: string[];
  warnings: string[];
  headers: { from: string; to: string; cc: string; bcc: string; subject: string; threadId: string };
  body: { hasText: boolean; hasHtml: boolean; preview: string; textParagraphs: number; htmlBlocks: number };
  signature: { required: boolean; matches: number; images: number; assets: RemoteAssetResult[] };
  attachments: Array<{ filename: string; mimeType: string; size: number; attachmentId: string }>;
}

export interface RemoteAssetResult {
  url: string;
  status: 'reachable' | 'unreachable' | 'unsupported' | 'unchecked';
  httpStatus?: number;
  reason?: string;
}

interface MimeContent {
  text: string[];
  html: string[];
  attachments: DraftInspection['attachments'];
}

export function inspectDraftPayload(
  draft: gmail_v1.Schema$Draft,
  options: InspectDraftOptions,
  signatureHtml?: string,
): DraftInspection {
  const errors: string[] = [];
  const warnings: string[] = [];
  const content: MimeContent = { text: [], html: [], attachments: [] };
  const payload = draft.message?.payload;
  if (payload) collectMimeContent(payload, content);

  const text = content.text.join('\n\n').trim();
  const html = content.html.join('').trim();
  const required = options.requireSignature === true;
  const checkAssets = options.checkRemoteSignatureAssets ?? required;
  const signatureFingerprint = required && signatureHtml
    ? fingerprintSignature(signatureHtml)
    : undefined;
  const matches = signatureFingerprint && containsSignature(html, signatureFingerprint)
    ? countSignatureMatches(html, signatureFingerprint)
    : 0;
  const signatureBoundary = matches > 0 && signatureFingerprint
    ? findSignatureBoundary(html, signatureFingerprint)
    : html.length;
  const messageHtml = html.slice(0, signatureBoundary);
  const textParagraphs = countTextParagraphs(text);
  const htmlBlocks = countHtmlBlocks(messageHtml);
  const imageUrls = signatureHtml ? extractImageUrls(signatureHtml) : [];
  const boundedAssets = imageUrls.slice(0, MAX_REMOTE_ASSETS).map(url => ({
    url: sanitizeUrl(url),
    status: 'unchecked' as const,
  }));

  if (!text && !html) errors.push('Draft has no message body');
  if (options.requireHtml && !html) errors.push('Draft does not contain an HTML body');
  if (html && textParagraphs > 1 && htmlBlocks < textParagraphs) {
    errors.push('HTML body does not preserve the plain-text paragraph structure');
  }
  if (checkAssets && !required) {
    errors.push('Remote signature assets cannot be checked when a signature is not required');
  }
  if (required && !signatureHtml) {
    errors.push('Required signature HTML was not provided');
  } else if (required && matches === 0) {
    errors.push('Required signature fingerprint is missing');
  } else if (required && matches > 1) {
    errors.push('Signature fingerprint appears more than once');
  }
  if (imageUrls.length > MAX_REMOTE_ASSETS) {
    errors.push(`Signature contains more than ${MAX_REMOTE_ASSETS} remote assets`);
  }

  validateAttachments(content.attachments, options.expectedAttachments, errors);

  const headers = payload?.headers ?? [];
  const result: DraftInspection = {
    verdict: errors.length ? 'NOT_READY' : 'READY',
    errors,
    warnings,
    headers: {
      from: headerValue(headers, 'from'),
      to: headerValue(headers, 'to'),
      cc: headerValue(headers, 'cc'),
      bcc: headerValue(headers, 'bcc'),
      subject: headerValue(headers, 'subject'),
      threadId: draft.message?.threadId ?? '',
    },
    body: {
      hasText: Boolean(text),
      hasHtml: Boolean(html),
      preview: makePreview(text || htmlToText(html)),
      textParagraphs,
      htmlBlocks,
    },
    signature: {
      required,
      matches,
      images: imageUrls.length,
      assets: boundedAssets,
    },
    attachments: content.attachments,
  };

  return result;
}

export async function probeRemoteAsset(url: string, timeoutMs = DEFAULT_PROBE_TIMEOUT_MS): Promise<RemoteAssetResult> {
  let current: URL;
  try {
    current = new URL(url);
  } catch {
    return { url: sanitizeUrl(url), status: 'unsupported', reason: 'Invalid URL' };
  }

  if (!/^https?:$/.test(current.protocol)) {
    return { url: sanitizeUrl(url), status: 'unsupported', reason: `Unsupported protocol: ${current.protocol}` };
  }
  if (current.username || current.password) {
    return { url: sanitizeUrl(current.toString()), status: 'unreachable', reason: 'URLs containing credentials are not allowed' };
  }

  const controller = new AbortController();
  const effectiveTimeout = Math.max(1, timeoutMs);
  const timer = setTimeout(() => controller.abort(), effectiveTimeout);

  try {
    for (let redirects = 0; ; redirects += 1) {
      const unsafeReason = await validatePublicTarget(current, controller.signal);
      if (unsafeReason) {
        return { url: sanitizeUrl(current.toString()), status: 'unreachable', reason: unsafeReason };
      }

      const response = await fetch(current, {
        method: 'HEAD',
        redirect: 'manual',
        signal: controller.signal,
      });

      if (isRedirect(response.status)) {
        await cancelBody(response);
        const location = response.headers.get('location');
        if (!location || redirects >= MAX_REDIRECTS) {
          return {
            url: sanitizeUrl(current.toString()),
            status: 'unreachable',
            httpStatus: response.status,
            reason: location ? `Redirect limit of ${MAX_REDIRECTS} exceeded` : 'Redirect is missing a Location header',
          };
        }
        current = new URL(location, current);
        if (!/^https?:$/.test(current.protocol)) {
          return { url: sanitizeUrl(current.toString()), status: 'unsupported', reason: `Unsupported protocol: ${current.protocol}` };
        }
        if (current.username || current.password) {
          return { url: sanitizeUrl(current.toString()), status: 'unreachable', reason: 'URLs containing credentials are not allowed' };
        }
        continue;
      }

      if (response.status === 405 || response.status === 501) {
        await cancelBody(response);
        const fallbackUnsafeReason = await validatePublicTarget(current, controller.signal);
        if (fallbackUnsafeReason) {
          return {
            url: sanitizeUrl(current.toString()),
            status: 'unreachable',
            reason: fallbackUnsafeReason,
          };
        }
        const fallback = await fetch(current, {
          method: 'GET',
          headers: { Range: 'bytes=0-0' },
          redirect: 'manual',
          signal: controller.signal,
        });
        const result = terminalProbeResult(current, fallback.status);
        await cancelBody(fallback);
        return result;
      }

      const result = terminalProbeResult(current, response.status);
      await cancelBody(response);
      return result;
    }
  } catch (error) {
    const timedOut = controller.signal.aborted;
    return {
      url: sanitizeUrl(current.toString()),
      status: 'unreachable',
      reason: timedOut ? 'Request timed out' : safeErrorReason(error),
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function inspectDraft(
  draft: gmail_v1.Schema$Draft,
  options: InspectDraftOptions,
  signatureHtml?: string,
): Promise<DraftInspection> {
  const result = inspectDraftPayload(draft, options, signatureHtml);
  const checkAssets = options.checkRemoteSignatureAssets ?? options.requireSignature === true;
  if (!checkAssets || !options.requireSignature || result.signature.matches !== 1) return result;

  const sourceAssetUrls = signatureHtml
    ? extractImageUrls(signatureHtml).slice(0, MAX_REMOTE_ASSETS)
    : [];
  result.signature.assets = await Promise.all(
    sourceAssetUrls.map(assetUrl => probeRemoteAsset(assetUrl)),
  );
  for (const asset of result.signature.assets) {
    if (asset.status !== 'reachable') {
      result.errors.push(`Signature asset is not reachable: ${asset.url}`);
    }
  }
  result.verdict = result.errors.length ? 'NOT_READY' : 'READY';
  return result;
}

function collectMimeContent(part: gmail_v1.Schema$MessagePart, content: MimeContent): void {
  if (part.filename) {
    content.attachments.push({
      filename: part.filename,
      mimeType: part.mimeType ?? '',
      size: part.body?.size ?? 0,
      attachmentId: part.body?.attachmentId ?? '',
    });
  } else if (part.body?.data) {
    const decoded = decodeBase64Url(part.body.data);
    if (part.mimeType?.toLowerCase() === 'text/plain') content.text.push(decoded);
    if (part.mimeType?.toLowerCase() === 'text/html') content.html.push(decoded);
  }

  for (const child of part.parts ?? []) collectMimeContent(child, content);
}

function decodeBase64Url(value: string): string {
  try {
    return Buffer.from(value, 'base64url').toString('utf8');
  } catch {
    return '';
  }
}

function headerValue(headers: gmail_v1.Schema$MessagePartHeader[], name: string): string {
  return headers.find(header => header.name?.toLowerCase() === name)?.value ?? '';
}

function countTextParagraphs(text: string): number {
  return text ? text.split(/\r?\n\s*\r?\n/).filter(paragraph => paragraph.trim()).length : 0;
}

/**
 * Formatting heuristic: paragraphs, list/table containers, and double-BR separators
 * are body-level blocks. Rows and list items deliberately do not increase the count.
 */
function countHtmlBlocks(html: string): number {
  if (!normalizeText(htmlToText(html))) return 0;

  let containers = 0;
  let paragraphs = 0;
  let containerDepth = 0;
  let paragraphDepth = 0;
  let consecutiveBreaks = 0;
  let breakSeparators = 0;
  let previousTagEnd = 0;
  const tags = html.matchAll(/<\/?(?:table|ul|ol|p)\b[^>]*>|<br\b[^>]*>/gi);

  for (const match of tags) {
    if (normalizeText(htmlToText(html.slice(previousTagEnd, match.index)))) consecutiveBreaks = 0;
    previousTagEnd = (match.index ?? 0) + match[0].length;
    const tag = match[0].toLowerCase();
    if (/^<\/(?:table|ul|ol)/.test(tag)) {
      if (containerDepth > 0) {
        containerDepth -= 1;
        if (containerDepth === 0) containers += 1;
      }
      continue;
    }
    if (/^<(?:table|ul|ol)\b/.test(tag)) {
      containerDepth += 1;
      consecutiveBreaks = 0;
      continue;
    }
    if (/^<\/p\b/.test(tag)) {
      if (containerDepth === 0 && paragraphDepth > 0) {
        paragraphDepth -= 1;
        paragraphs += 1;
      }
      continue;
    }
    if (/^<p\b/.test(tag)) {
      if (containerDepth === 0) paragraphDepth += 1;
      consecutiveBreaks = 0;
      continue;
    }
    if (containerDepth === 0 && /^<br\b/.test(tag)) {
      consecutiveBreaks += 1;
      if (consecutiveBreaks % 2 === 0) breakSeparators += 1;
    }
  }

  return Math.max(1, containers + paragraphs, breakSeparators + 1);
}

function countSignatureMatches(bodyHtml: string, fingerprint: SignatureFingerprint): number {
  if (fingerprint.text) {
    const bodyText = fingerprintSignature(bodyHtml).text;
    return countOccurrences(bodyText, fingerprint.text);
  }

  if (!fingerprint.assetPaths.length) return 0;
  const bodyAssets = extractPublicAssetPaths(bodyHtml);
  return Math.min(...fingerprint.assetPaths.map(path => bodyAssets.filter(candidate => candidate === path).length));
}

function countOccurrences(value: string, search: string): number {
  let count = 0;
  let start = 0;
  while (search && (start = value.indexOf(search, start)) !== -1) {
    count += 1;
    start += search.length;
  }
  return count;
}

function findSignatureBoundary(bodyHtml: string, fingerprint: SignatureFingerprint): number {
  const lowerHtml = decodeHtmlEntities(bodyHtml).toLowerCase();
  const candidates: number[] = [];
  const textTokens = fingerprint.text.match(/[\p{L}\p{N}@._-]{3,}/gu) ?? [];
  for (const token of textTokens) {
    const index = lowerHtml.indexOf(token.toLowerCase());
    if (index >= 0) candidates.push(index);
  }
  for (const path of fingerprint.assetPaths) {
    const index = lowerHtml.indexOf(path.toLowerCase());
    if (index >= 0) candidates.push(index);
  }
  return candidates.length ? Math.min(...candidates) : bodyHtml.length;
}

function extractImageUrls(html: string): string[] {
  const urls = [...html.matchAll(/<img\b[^>]*\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)]
    .map(match => decodeHtmlEntities(match[1] ?? match[2] ?? match[3] ?? ''))
    .filter(Boolean);
  return [...new Set(urls)];
}

function extractPublicAssetPaths(html: string): string[] {
  return [...html.matchAll(/\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)]
    .map(match => decodeHtmlEntities(match[1] ?? match[2] ?? match[3] ?? ''))
    .map(value => {
      try {
        const url = new URL(value);
        return /^https?:$/.test(url.protocol) ? `${url.origin}${url.pathname}` : undefined;
      } catch {
        return undefined;
      }
    })
    .filter((path): path is string => Boolean(path));
}

function validateAttachments(
  attachments: DraftInspection['attachments'],
  expected: string[] | undefined,
  errors: string[],
): void {
  for (const attachment of attachments) {
    if (attachment.size <= 0) errors.push(`Attachment is zero-byte: ${attachment.filename}`);
  }

  if (!expected) return;

  const remainingActual = attachments.map(attachment => attachmentBasename(attachment.filename));
  for (const expectedName of expected) {
    const index = remainingActual.indexOf(expectedName);
    if (index === -1) errors.push(`Missing expected attachment: ${expectedName}`);
    else remainingActual.splice(index, 1);
  }
  for (const unexpected of remainingActual) errors.push(`Unexpected attachment: ${unexpected}`);
}

function attachmentBasename(filename: string): string {
  return filename.split(/[\\/]/).pop() ?? filename;
}

function makePreview(value: string): string {
  return normalizeText(value).slice(0, MAX_PREVIEW_LENGTH);
}

function htmlToText(html: string): string {
  return decodeHtmlEntities(
    html
      .replace(/<(?:script|style)\b[^>]*>[\s\S]*?<\/(?:script|style)>/gi, ' ')
      .replace(/<(?:br|\/p|\/div|\/tr|\/li|\/table|\/h[1-6])\b[^>]*>/gi, ' ')
      .replace(/<[^>]*>/g, ' '),
  );
}

function decodeHtmlEntities(value: string): string {
  const named: Record<string, string> = { amp: '&', apos: "'", gt: '>', lt: '<', nbsp: ' ', quot: '"' };
  return value.replace(/&(#x[\da-f]+|#\d+|[a-z]+);/gi, (entity, encoded) => {
    if (encoded[0] === '#') {
      const codePoint = encoded[1].toLowerCase() === 'x'
        ? Number.parseInt(encoded.slice(2), 16)
        : Number.parseInt(encoded.slice(1), 10);
      return Number.isNaN(codePoint) ? entity : String.fromCodePoint(codePoint);
    }
    return named[encoded.toLowerCase()] ?? entity;
  });
}

function normalizeText(value: string): string {
  return value.replace(/\s+/g, ' ').trim().toLowerCase();
}

function isRedirect(status: number): boolean {
  return status >= 300 && status < 400;
}

function terminalProbeResult(url: URL, status: number): RemoteAssetResult {
  return status >= 200 && status < 300
    ? { url: sanitizeUrl(url.toString()), status: 'reachable', httpStatus: status }
    : { url: sanitizeUrl(url.toString()), status: 'unreachable', httpStatus: status, reason: `HTTP ${status}` };
}

async function cancelBody(response: Response): Promise<void> {
  try {
    await response.body?.cancel();
  } catch {
    // The response verdict is independent of transport cleanup errors.
  }
}

async function validatePublicTarget(url: URL, signal: AbortSignal): Promise<string | undefined> {
  if (url.username || url.password) return 'URLs containing credentials are not allowed';
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (!hostname) return 'URL hostname is missing';

  const ipVersion = isIP(hostname);
  if (ipVersion) return isPublicAddress(hostname) ? undefined : `Non-public address rejected: ${hostname}`;

  let addresses: Array<{ address: string }>;
  try {
    addresses = await raceAbort(dns.lookup(hostname, { all: true, verbatim: true }), signal);
  } catch (error) {
    if (signal.aborted) throw error;
    return `DNS lookup failed for ${hostname}`;
  }
  if (!addresses.length) return `DNS lookup returned no addresses for ${hostname}`;

  const unsafe = addresses.find(result => !isPublicAddress(result.address));
  return unsafe ? `Non-public address rejected for ${hostname}: ${unsafe.address}` : undefined;
}

function raceAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new Error('aborted'));
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new Error('aborted'));
    signal.addEventListener('abort', onAbort, { once: true });
    promise.then(
      value => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      error => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

function isPublicAddress(address: string): boolean {
  if (isIP(address) === 4) return isPublicIpv4(address);
  if (isIP(address) !== 6) return false;

  const bytes = ipv6Bytes(address);
  if (!bytes) return false;
  if (bytes.slice(0, 10).every(value => value === 0) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return isPublicIpv4(bytes.slice(12).join('.'));
  }
  if (bytes.slice(0, 12).every(value => value === 0)) return false;
  if (bytes[0] === 0xff) return false;
  if ((bytes[0] & 0xfe) === 0xfc) return false;
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return false;
  return true;
}

function isPublicIpv4(address: string): boolean {
  const octets = address.split('.').map(Number);
  if (octets.length !== 4 || octets.some(octet => !Number.isInteger(octet) || octet < 0 || octet > 255)) return false;
  const [a, b] = octets;
  if (a === 0 || a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a >= 224) return false;
  return true;
}

function ipv6Bytes(address: string): number[] | undefined {
  let normalized = address.toLowerCase().split('%')[0];
  const embeddedIpv4 = normalized.match(/(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (embeddedIpv4) {
    const octets = embeddedIpv4.split('.').map(Number);
    if (octets.some(octet => octet < 0 || octet > 255)) return undefined;
    normalized = normalized.replace(embeddedIpv4, `${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`);
  }

  const halves = normalized.split('::');
  if (halves.length > 2) return undefined;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if ((halves.length === 1 && missing !== 0) || missing < 0) return undefined;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return undefined;

  const bytes: number[] = [];
  for (const group of groups) {
    if (!/^[\da-f]{1,4}$/.test(group)) return undefined;
    const value = Number.parseInt(group, 16);
    bytes.push(value >> 8, value & 0xff);
  }
  return bytes;
}

function sanitizeUrl(value: string): string {
  try {
    const url = new URL(value);
    if (!/^https?:$/.test(url.protocol)) return url.protocol;
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return value.split(/[?#]/, 1)[0].slice(0, MAX_PREVIEW_LENGTH);
  }
}

function safeErrorReason(error: unknown): string {
  if (error instanceof Error && error.name === 'AbortError') return 'Request timed out';
  return 'Remote asset request failed';
}
