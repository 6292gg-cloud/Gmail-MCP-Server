import { promises as dns } from 'node:dns';
import { createHash } from 'node:crypto';
import http, { type IncomingMessage, type RequestOptions } from 'node:http';
import https from 'node:https';
import { isIP } from 'node:net';
import type { gmail_v1 } from 'googleapis';
import { containsSignature, fingerprintSignature, type SignatureFingerprint } from './signature.js';

const MAX_PREVIEW_LENGTH = 500;
const MAX_REMOTE_ASSETS = 20;
const DEFAULT_PROBE_TIMEOUT_MS = 3000;
const MAX_REDIRECTS = 2;

export interface InspectDraftOptions {
  expectedHeaders?: ExpectedDraftHeaders;
  expectedBody?: string;
  expectedHtmlBody?: string;
  expectedAttachments?: string[];
  requireSignature?: boolean;
  requireHtml?: boolean;
  checkRemoteSignatureAssets?: boolean;
  includeHtmlComparisonDiagnostics?: boolean;
}

export interface ExpectedDraftHeaders {
  from?: string;
  to?: string[];
  cc?: string[];
  bcc?: string[];
  subject?: string;
}

export interface DraftInspection {
  verdict: 'READY' | 'NOT_READY';
  errors: string[];
  warnings: string[];
  headers: { from: string; to: string; cc: string; bcc: string; subject: string; threadId: string };
  body: { hasText: boolean; hasHtml: boolean; preview: string; textParagraphs: number; htmlBlocks: number };
  signature: { required: boolean; matches: number; images: number; assets: RemoteAssetResult[] };
  attachments: Array<{ filename: string; mimeType: string; size: number; attachmentId: string }>;
  diagnostics?: { htmlComparison: HtmlComparisonDiagnostics };
}

interface HtmlComparisonDiagnostics {
  actualLength: number;
  expectedLength: number;
  commonPrefixLength: number;
  commonSuffixLength: number;
  actualSha256: string;
  expectedSha256: string;
  actualShape: string;
  expectedShape: string;
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

interface SignatureRegion {
  start: number;
  end: number;
  html: string;
}

interface ResolvedTarget {
  address: string;
  family: 4 | 6;
}

interface PinnedResponse {
  status: number;
  location?: string;
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

  const rawText = content.text.join('\n\n');
  const rawHtml = content.html.join('');
  const text = rawText.trim();
  const html = rawHtml.trim();
  const required = options.requireSignature === true;
  const checkAssets = options.checkRemoteSignatureAssets ?? required;
  const signatureFingerprint = required && signatureHtml
    ? fingerprintSignature(signatureHtml)
    : undefined;
  const matches = signatureFingerprint && containsSignature(rawHtml, signatureFingerprint)
    ? countSignatureMatches(rawHtml, signatureFingerprint)
    : 0;
  const signatureRegion = matches > 0 && signatureFingerprint
    ? findSignatureRegion(rawHtml, signatureFingerprint)
    : undefined;
  const htmlBeforeSignature = rawHtml.slice(0, signatureRegion?.start ?? rawHtml.length);
  const comparableHtml = signatureRegion
    ? `${removeAppliedSignatureSeparator(htmlBeforeSignature)}${rawHtml.slice(signatureRegion.end)}`
    : rawHtml;
  const messageHtml = comparableHtml.trim();
  const textParagraphs = countTextParagraphs(text);
  const htmlBlocks = countHtmlBlocks(messageHtml);
  const draftSignatureHtml = signatureRegion?.html ?? '';
  const imageUrls = extractImageUrls(draftSignatureHtml);
  const imageElements = countImageElements(draftSignatureHtml);
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
  if (required && matches === 1 && signatureFingerprint) {
    const actualAssetPaths = [...new Set(extractPublicAssetPaths(draftSignatureHtml))].sort();
    if (!sameStrings(actualAssetPaths, signatureFingerprint.assetPaths)) {
      errors.push('Draft signature assets do not match the expected signature assets');
    }
  }
  if (imageUrls.length > MAX_REMOTE_ASSETS) {
    errors.push(`Signature contains more than ${MAX_REMOTE_ASSETS} remote assets`);
  }

  validateAttachments(content.attachments, options.expectedAttachments, errors);

  const headers = payload?.headers ?? [];
  validateExpectedHeaders(headers, options.expectedHeaders, errors);
  validateExpectedBody(rawText, comparableHtml, options, errors);
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
      images: imageElements,
      assets: boundedAssets,
    },
    attachments: content.attachments,
  };
  if (options.includeHtmlComparisonDiagnostics && options.expectedHtmlBody !== undefined) {
    result.diagnostics = {
      htmlComparison: buildHtmlComparisonDiagnostics(comparableHtml, options.expectedHtmlBody),
    };
  }

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
    let redirects = 0;
    let usedRangeFallback = false;
    while (true) {
      const headResolution = await resolvePublicTarget(current, controller.signal);
      if ('reason' in headResolution) {
        return { url: sanitizeUrl(current.toString()), status: 'unreachable', reason: headResolution.reason };
      }

      const response = await requestPinned(current, headResolution.target, 'HEAD', controller.signal);
      if (isRedirect(response.status)) {
        const redirect = nextRedirect(current, response, redirects);
        if ('result' in redirect) return redirect.result;
        current = redirect.url;
        redirects += 1;
        continue;
      }

      if (response.status === 405 || response.status === 501) {
        if (usedRangeFallback) return terminalProbeResult(current, response.status);
        usedRangeFallback = true;
        const fallbackResolution = await resolvePublicTarget(current, controller.signal);
        if ('reason' in fallbackResolution) {
          return {
            url: sanitizeUrl(current.toString()),
            status: 'unreachable',
            reason: fallbackResolution.reason,
          };
        }
        const fallback = await requestPinned(current, fallbackResolution.target, 'GET', controller.signal);
        if (isRedirect(fallback.status)) {
          const redirect = nextRedirect(current, fallback, redirects);
          if ('result' in redirect) return redirect.result;
          current = redirect.url;
          redirects += 1;
          continue;
        }
        return terminalProbeResult(current, fallback.status);
      }

      return terminalProbeResult(current, response.status);
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

  const content: MimeContent = { text: [], html: [], attachments: [] };
  if (draft.message?.payload) collectMimeContent(draft.message.payload, content);
  const bodyHtml = content.html.join('').trim();
  const fingerprint = signatureHtml ? fingerprintSignature(signatureHtml) : undefined;
  const region = fingerprint ? findSignatureRegion(bodyHtml, fingerprint) : undefined;
  const sourceAssetUrls = region
    ? extractImageUrls(region.html).slice(0, MAX_REMOTE_ASSETS)
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

function validateExpectedHeaders(
  headers: gmail_v1.Schema$MessagePartHeader[],
  expected: ExpectedDraftHeaders | undefined,
  errors: string[],
): void {
  if (!expected) return;
  const fields: Array<[keyof ExpectedDraftHeaders, string]> = [
    ['from', 'From'],
    ['to', 'To'],
    ['cc', 'Cc'],
    ['bcc', 'Bcc'],
    ['subject', 'Subject'],
  ];

  for (const [field, label] of fields) {
    const expectedField = expected[field];
    if (expectedField === undefined) continue;
    const expectedValue = Array.isArray(expectedField) ? expectedField.join(', ') : expectedField;
    const actualValue = headerValue(headers, field);
    if (canonicalizeLineEndings(actualValue) !== canonicalizeLineEndings(expectedValue)) {
      errors.push(`Draft ${label} header does not match expected value`);
    }
  }
}

function validateExpectedBody(
  text: string,
  html: string,
  options: InspectDraftOptions,
  errors: string[],
): void {
  if (
    options.expectedBody !== undefined
    && canonicalizeLineEndings(text) !== canonicalizeLineEndings(options.expectedBody)
  ) {
    errors.push('Draft plain-text body does not match expected content');
  }
  if (
    options.expectedHtmlBody !== undefined
    && canonicalizeHtmlForComparison(html) !== canonicalizeHtmlForComparison(options.expectedHtmlBody)
  ) {
    errors.push('Draft HTML body does not match expected content');
  }
}

function canonicalizeLineEndings(value: string): string {
  return value.replace(/\r\n?/g, '\n');
}

function canonicalizeHtmlForComparison(value: string): string {
  return canonicalizeLineEndings(value).trim();
}

function buildHtmlComparisonDiagnostics(actualHtml: string, expectedHtml: string): HtmlComparisonDiagnostics {
  const actual = canonicalizeHtmlForComparison(actualHtml);
  const expected = canonicalizeHtmlForComparison(expectedHtml);
  let commonPrefixLength = 0;
  while (
    commonPrefixLength < actual.length
    && commonPrefixLength < expected.length
    && actual[commonPrefixLength] === expected[commonPrefixLength]
  ) {
    commonPrefixLength += 1;
  }

  let commonSuffixLength = 0;
  while (
    commonSuffixLength < actual.length - commonPrefixLength
    && commonSuffixLength < expected.length - commonPrefixLength
    && actual[actual.length - commonSuffixLength - 1] === expected[expected.length - commonSuffixLength - 1]
  ) {
    commonSuffixLength += 1;
  }

  return {
    actualLength: actual.length,
    expectedLength: expected.length,
    commonPrefixLength,
    commonSuffixLength,
    actualSha256: createHash('sha256').update(actual).digest('hex'),
    expectedSha256: createHash('sha256').update(expected).digest('hex'),
    actualShape: describeHtmlShape(actual),
    expectedShape: describeHtmlShape(expected),
  };
}

function describeHtmlShape(html: string): string {
  const tokens = html.match(/<!--[\s\S]*?-->|<\/?[a-z][^>]*>|&(?:#[xX][\da-fA-F]+|#\d+|[a-zA-Z]+);|\s+|[^<&\s]+|[<&]/g) ?? [];
  const described = tokens.slice(0, 120).map(token => {
    if (token.startsWith('<!--')) return '<comment>';
    const tag = token.match(/^<(\/)?([a-z][\w:-]*)/i);
    if (tag) return `<${tag[1] ?? ''}${tag[2].toLowerCase()}${/\/\s*>$/.test(token) ? '/' : ''}>`;
    if (/^&/.test(token)) return '{entity}';
    if (/^\s+$/.test(token)) return `{ws:${token.length}}`;
    return `{text:${token.length}}`;
  });
  if (tokens.length > 120) described.push(`{truncated:${tokens.length - 120}}`);
  return described.join('');
}

function removeAppliedSignatureSeparator(html: string): string {
  return html.replace(/<br\s*\/?>[ \t\r\n]*<br\s*\/?>[ \t\r\n]*$/i, '');
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

function findSignatureRegion(bodyHtml: string, fingerprint: SignatureFingerprint): SignatureRegion | undefined {
  const lowerHtml = bodyHtml.toLowerCase();
  const assetCandidates: Array<{ start: number; end: number }> = [];
  const expectedAssetPaths = new Set(fingerprint.assetPaths.map(path => path.toLowerCase()));
  for (const attribute of extractHtmlAssetAttributes(bodyHtml)) {
    const path = publicAssetPath(attribute.value)?.toLowerCase();
    if (path && expectedAssetPaths.has(path)) {
      assetCandidates.push({ start: attribute.start, end: attribute.end });
    }
  }

  const firstAsset = assetCandidates.length
    ? Math.min(...assetCandidates.map(candidate => candidate.start))
    : undefined;
  const assetBoundary = firstAsset === undefined
    ? undefined
    : findAssetBackedSignatureStart(bodyHtml, firstAsset, fingerprint);
  const textSearchStart = assetBoundary
    ?? (firstAsset === undefined ? 0 : findEnclosingBlockStart(bodyHtml, firstAsset));
  const candidates = [...assetCandidates];
  const textTokens = fingerprint.text.match(/[\p{L}\p{N}@._-]{3,}/gu) ?? [];
  for (const token of textTokens) {
    const index = lowerHtml.indexOf(token.toLowerCase(), textSearchStart);
    if (index >= 0) candidates.push({ start: index, end: index + token.length });
  }
  if (!candidates.length) return undefined;

  const firstEvidence = Math.min(...candidates.map(candidate => candidate.start));
  const lastEvidence = Math.max(...candidates.map(candidate => candidate.end));
  const enclosingStart = findEnclosingBlockStart(bodyHtml, firstEvidence);
  const fallbackStart = rewindEmptyBlockSiblings(bodyHtml, enclosingStart);
  const start = assetBoundary ?? findAppliedSignatureStart(bodyHtml, enclosingStart) ?? fallbackStart;
  const evidenceEnd = findSignatureFragmentEnd(bodyHtml, start, lastEvidence) ?? lastEvidence;
  const end = advanceOverEmptyBlockSiblings(bodyHtml, evidenceEnd);
  return { start, end, html: bodyHtml.slice(start, end) };
}

function findAssetBackedSignatureStart(
  html: string,
  firstAsset: number,
  fingerprint: SignatureFingerprint,
): number | undefined {
  const prefix = html.slice(0, firstAsset);
  const separators = [...prefix.matchAll(/<br\s*\/?>[ \t\r\n]*<br\s*\/?>/gi)];
  for (let index = separators.length - 1; index >= 0; index -= 1) {
    const separator = separators[index];
    const boundary = (separator.index ?? 0) + separator[0].length;
    if (containsSignature(html.slice(boundary), fingerprint)) return boundary;
  }
  return undefined;
}

function findAppliedSignatureStart(html: string, enclosingStart: number): number | undefined {
  const prefix = html.slice(0, enclosingStart);
  const separators = [...prefix.matchAll(/<br\s*\/?>[ \t\r\n]*<br\s*\/?>/gi)];
  for (let index = separators.length - 1; index >= 0; index -= 1) {
    const separator = separators[index];
    const boundary = (separator.index ?? 0) + separator[0].length;
    const preamble = html.slice(boundary, enclosingStart);
    if (!normalizeText(htmlToText(preamble))) return boundary;
  }
  return undefined;
}

function findSignatureFragmentEnd(html: string, start: number, lastEvidence: number): number | undefined {
  const relativeEvidence = lastEvidence - start;
  const ranges = completedTopLevelBlocks(html.slice(start));
  const containing = ranges.find(range => range.start <= relativeEvidence && relativeEvidence <= range.end);
  return containing ? start + containing.end : findContainingStartTagEnd(html, lastEvidence);
}

function findContainingStartTagEnd(html: string, evidenceIndex: number): number | undefined {
  const tagStart = html.lastIndexOf('<', evidenceIndex);
  if (tagStart < 0 || !/^<[a-z]/i.test(html.slice(tagStart))) return undefined;

  let quote: '"' | "'" | undefined;
  for (let index = tagStart + 1; index < html.length; index += 1) {
    const character = html[index];
    if (quote) {
      if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (character === '>') return index >= evidenceIndex ? index + 1 : undefined;
    if (character === '<') return undefined;
  }
  return undefined;
}

function findEnclosingBlockStart(html: string, evidenceIndex: number): number {
  const stack: Array<{ tag: string; index: number }> = [];
  for (const match of html.matchAll(/<\/?(table|ul|ol|p|div)\b[^>]*>/gi)) {
    const index = match.index ?? 0;
    if (index >= evidenceIndex) break;
    const tag = match[1].toLowerCase();
    if (match[0].startsWith('</')) {
      for (let cursor = stack.length - 1; cursor >= 0; cursor -= 1) {
        if (stack[cursor].tag === tag) {
          stack.splice(cursor, 1);
          break;
        }
      }
    } else {
      stack.push({ tag, index });
    }
  }
  const preferred = [...stack].reverse().find(entry => /^(?:table|ul|ol|p)$/.test(entry.tag));
  return preferred?.index ?? stack[stack.length - 1]?.index ?? evidenceIndex;
}

function rewindEmptyBlockSiblings(html: string, initialStart: number): number {
  let start = initialStart;
  while (start > 0) {
    const ranges = completedTopLevelBlocks(html.slice(0, start));
    const previous = ranges[ranges.length - 1];
    if (!previous || html.slice(previous.end, start).trim() || normalizeText(htmlToText(html.slice(previous.start, previous.end)))) {
      break;
    }
    start = previous.start;
  }
  return start;
}

function advanceOverEmptyBlockSiblings(html: string, initialEnd: number): number {
  let end = initialEnd;
  while (end < html.length) {
    const whitespaceLength = html.slice(end).match(/^\s*/)?.[0].length ?? 0;
    const nextStart = end + whitespaceLength;
    const next = completedTopLevelBlocks(html.slice(nextStart))[0];
    if (!next || next.start !== 0) break;

    const fragment = html.slice(nextStart, nextStart + next.end);
    if (normalizeText(htmlToText(fragment)) || extractHtmlAssetAttributes(fragment).length) break;
    end = nextStart + next.end;
  }
  return end;
}

function completedTopLevelBlocks(html: string): Array<{ start: number; end: number }> {
  const ranges: Array<{ start: number; end: number }> = [];
  const stack: Array<{ tag: string; index: number }> = [];
  for (const match of html.matchAll(/<\/?(div|table|ul|ol|p)\b[^>]*>/gi)) {
    const tag = match[1].toLowerCase();
    if (!match[0].startsWith('</')) {
      stack.push({ tag, index: match.index ?? 0 });
      continue;
    }
    for (let cursor = stack.length - 1; cursor >= 0; cursor -= 1) {
      if (stack[cursor].tag !== tag) continue;
      const [opened] = stack.splice(cursor, 1);
      if (stack.length === 0) ranges.push({ start: opened.index, end: (match.index ?? 0) + match[0].length });
      break;
    }
  }
  return ranges;
}

function extractImageUrls(html: string): string[] {
  const urls = [...html.matchAll(/<img\b[^>]*>/gi)]
    .flatMap(match => extractHtmlAssetAttributes(match[0]))
    .filter(attribute => attribute.name === 'src')
    .map(attribute => attribute.value)
    .filter(Boolean);
  return [...new Set(urls)];
}

function countImageElements(html: string): number {
  return [...html.matchAll(/<img\b/gi)].length;
}

function extractPublicAssetPaths(html: string): string[] {
  return extractHtmlAssetAttributes(html)
    .map(attribute => publicAssetPath(attribute.value))
    .filter((path): path is string => Boolean(path));
}

interface HtmlAssetAttribute {
  name: 'src' | 'href';
  value: string;
  start: number;
  end: number;
}

function extractHtmlAssetAttributes(html: string): HtmlAssetAttribute[] {
  return [...html.matchAll(/\b(src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)]
    .map(match => ({
      name: match[1].toLowerCase() as HtmlAssetAttribute['name'],
      value: decodeHtmlEntities(match[2] ?? match[3] ?? match[4] ?? ''),
      start: match.index ?? 0,
      end: (match.index ?? 0) + match[0].length,
    }));
}

function publicAssetPath(value: string): string | undefined {
  try {
    const url = new URL(value);
    return /^https?:$/.test(url.protocol) ? `${url.origin}${url.pathname}` : undefined;
  } catch {
    return undefined;
  }
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
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

function nextRedirect(
  current: URL,
  response: PinnedResponse,
  redirects: number,
): { url: URL } | { result: RemoteAssetResult } {
  if (!response.location || redirects >= MAX_REDIRECTS) {
    return {
      result: {
        url: sanitizeUrl(current.toString()),
        status: 'unreachable',
        httpStatus: response.status,
        reason: response.location
          ? `Redirect limit of ${MAX_REDIRECTS} exceeded`
          : 'Redirect is missing a Location header',
      },
    };
  }

  let url: URL;
  try {
    url = new URL(response.location, current);
  } catch {
    return {
      result: {
        url: sanitizeUrl(current.toString()),
        status: 'unreachable',
        httpStatus: response.status,
        reason: 'Redirect Location is invalid',
      },
    };
  }
  if (!/^https?:$/.test(url.protocol)) {
    return { result: { url: sanitizeUrl(url.toString()), status: 'unsupported', reason: `Unsupported protocol: ${url.protocol}` } };
  }
  if (url.username || url.password) {
    return { result: { url: sanitizeUrl(url.toString()), status: 'unreachable', reason: 'URLs containing credentials are not allowed' } };
  }
  return { url };
}

async function resolvePublicTarget(
  url: URL,
  signal: AbortSignal,
): Promise<{ target: ResolvedTarget } | { reason: string }> {
  if (url.username || url.password) return { reason: 'URLs containing credentials are not allowed' };
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  if (!hostname) return { reason: 'URL hostname is missing' };

  const ipVersion = isIP(hostname);
  if (ipVersion) {
    return isPublicAddress(hostname)
      ? { target: { address: hostname, family: ipVersion as 4 | 6 } }
      : { reason: `Non-public address rejected: ${hostname}` };
  }

  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await raceAbort(dns.lookup(hostname, { all: true, verbatim: true }), signal);
  } catch (error) {
    if (signal.aborted) throw error;
    return { reason: `DNS lookup failed for ${hostname}` };
  }
  if (!addresses.length) return { reason: `DNS lookup returned no addresses for ${hostname}` };

  const unsafe = addresses.find(result => !isPublicAddress(result.address));
  if (unsafe) return { reason: `Non-public address rejected for ${hostname}: ${unsafe.address}` };
  const selected = addresses[0];
  return { target: { address: selected.address, family: selected.family as 4 | 6 } };
}

function requestPinned(
  url: URL,
  target: ResolvedTarget,
  method: 'HEAD' | 'GET',
  signal: AbortSignal,
): Promise<PinnedResponse> {
  return new Promise<PinnedResponse>((resolve, reject) => {
    const originalHostname = url.hostname.replace(/^\[|\]$/g, '');
    const options: RequestOptions & { servername?: string } = {
      protocol: url.protocol,
      hostname: target.address,
      family: target.family,
      port: url.port || undefined,
      path: `${url.pathname}${url.search}`,
      method,
      headers: {
        Host: url.host,
        ...(method === 'GET' ? { Range: 'bytes=0-0' } : {}),
      },
      signal,
      ...(url.protocol === 'https:' && !isIP(originalHostname) ? { servername: originalHostname } : {}),
    };
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request(options, (response: IncomingMessage) => {
      const locationHeader = response.headers.location;
      const location = Array.isArray(locationHeader) ? locationHeader[0] : locationHeader;
      const result: PinnedResponse = { status: response.statusCode ?? 0, ...(location ? { location } : {}) };
      response.destroy();
      resolve(result);
    });
    request.once('error', reject);
    request.end();
  });
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
