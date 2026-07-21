import type { gmail_v1 } from 'googleapis';

export interface EmailMessageArgs {
  to: string[];
  subject: string;
  body: string;
  from?: string;
  htmlBody?: string;
  mimeType?: 'text/plain' | 'text/html' | 'multipart/alternative';
  cc?: string[];
  bcc?: string[];
  threadId?: string;
  inReplyTo?: string;
  references?: string;
  attachments?: string[];
  includeSignature?: boolean;
}

export type SignatureStatus = 'not_requested' | 'applied' | 'already_present' | 'missing' | 'error';

export const NO_SIGNATURE_WARNING = 'No Gmail send-as signature is configured for this From address';

export interface SignatureLookup {
  status: 'found' | 'missing' | 'error';
  html?: string;
  warning?: string;
}

export interface SignatureResult {
  args: EmailMessageArgs;
  status: SignatureStatus;
  warning?: string;
  signatureHtml?: string;
}

export interface SignatureFingerprint {
  text: string;
  assetPaths: string[];
}

export function plainTextToHtml(body: string): string {
  return body
    .split(/\r?\n\s*\r?\n/)
    .map(paragraph => `<p>${escapeHtml(paragraph).replace(/\r?\n/g, '<br>')}</p>`)
    .join('');
}

export function fingerprintSignature(html: string): SignatureFingerprint {
  const assetPaths = [...new Set(
    [...html.matchAll(/\b(?:src|href)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi)]
      .map(match => match[1] ?? match[2] ?? match[3] ?? '')
      .map(publicAssetPath)
      .filter((path): path is string => Boolean(path))
  )].sort();

  return {
    text: normalizeText(htmlToText(html)),
    assetPaths,
  };
}

export function containsSignature(bodyHtml: string, fingerprint: SignatureFingerprint): boolean {
  const bodyText = normalizeText(htmlToText(bodyHtml));
  if (fingerprint.text) {
    return bodyText.includes(fingerprint.text);
  }

  if (!fingerprint.assetPaths.length) return false;

  const bodyAssets = new Set(fingerprintSignature(bodyHtml).assetPaths);
  return fingerprint.assetPaths.some(path => bodyAssets.has(path));
}

export async function resolveSignatureHtml(gmail: gmail_v1.Gmail, from?: string): Promise<SignatureLookup> {
  try {
    const response = await gmail.users.settings.sendAs.list({ userId: 'me' });
    const aliases = response.data.sendAs || [];
    const fromAddress = parseFromAddress(from);
    const chosen = (fromAddress
      ? aliases.find(alias => alias.sendAsEmail?.toLowerCase() === fromAddress)
      : undefined)
      || aliases.find(alias => alias.isDefault)
      || aliases.find(alias => alias.isPrimary)
      || aliases[0];
    const html = chosen?.signature?.trim();

    return html
      ? { status: 'found', html }
      : { status: 'missing', warning: NO_SIGNATURE_WARNING };
  } catch {
    return {
      status: 'error',
      warning: 'Unable to retrieve the Gmail send-as signature',
    };
  }
}

export async function applySignature(gmail: gmail_v1.Gmail, args: EmailMessageArgs): Promise<SignatureResult> {
  const nextArgs = { ...args };
  if (!nextArgs.includeSignature) {
    return { args: nextArgs, status: 'not_requested' };
  }

  const lookup = await resolveSignatureHtml(gmail, nextArgs.from);
  if (lookup.status === 'missing' || lookup.status === 'error') {
    return { args: nextArgs, status: lookup.status, warning: lookup.warning };
  }

  const bodyHtml = nextArgs.htmlBody || plainTextToHtml(nextArgs.body);
  const fingerprint = fingerprintSignature(lookup.html!);
  if (containsSignature(bodyHtml, fingerprint)) {
    return {
      args: promoteHtml(nextArgs),
      status: 'already_present',
      signatureHtml: lookup.html,
    };
  }

  return {
    args: promoteHtml({ ...nextArgs, htmlBody: `${bodyHtml}<br><br>${lookup.html}` }),
    status: 'applied',
    signatureHtml: lookup.html,
  };
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function parseFromAddress(from?: string): string | undefined {
  if (!from) return undefined;
  const match = from.match(/<\s*([^>\s]+@[^>\s]+)\s*>/);
  return (match?.[1] || from).trim().toLowerCase();
}

function promoteHtml(args: EmailMessageArgs): EmailMessageArgs {
  return !args.mimeType || args.mimeType === 'text/plain'
    ? { ...args, mimeType: 'multipart/alternative' }
    : args;
}

function publicAssetPath(value: string): string | undefined {
  try {
    const url = new URL(value);
    return /^https?:$/.test(url.protocol) ? `${url.origin}${url.pathname}` : undefined;
  } catch {
    return undefined;
  }
}

function htmlToText(html: string): string {
  return decodeHtmlEntities(
    html
      .replace(/<(?:script|style)\b[^>]*>[\s\S]*?<\/(?:script|style)>/gi, ' ')
      .replace(/<(?:br|\/p|\/div|\/tr|\/li|\/table|\/h[1-6])\b[^>]*>/gi, ' ')
      .replace(/<[^>]*>/g, ' ')
  );
}

function decodeHtmlEntities(value: string): string {
  const named: Record<string, string> = { amp: '&', apos: "'", gt: '>', lt: '<', nbsp: ' ', quot: '"' };
  return value.replace(/&(#x[\da-f]+|#\d+|[a-z]+);/gi, (entity, value) => {
    if (value[0] === '#') {
      const codePoint = value[1].toLowerCase() === 'x'
        ? Number.parseInt(value.slice(2), 16)
        : Number.parseInt(value.slice(1), 10);
      return Number.isNaN(codePoint) ? entity : String.fromCodePoint(codePoint);
    }
    return named[value.toLowerCase()] ?? entity;
  });
}

function normalizeText(value: string): string {
  return value.replace(/\s+/g, ' ').trim().toLowerCase();
}
