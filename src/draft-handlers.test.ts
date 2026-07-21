import type { gmail_v1 } from 'googleapis';
import { describe, expect, it, vi } from 'vitest';
import {
  DraftOperationalError,
  handleInspectDraft,
  handleUpdateDraft,
  renderToolError,
} from './draft-handlers.js';
import { applySignature, type EmailMessageArgs } from './signature.js';

function encoded(value: string): string {
  return Buffer.from(value).toString('base64url');
}

function draftFixture(options: { from?: string | null; text?: string; html?: string } = {}): gmail_v1.Schema$Draft {
  const headers = [
    ...(options.from === null ? [] : [{ name: 'From', value: options.from ?? 'Sender <sender@example.com>' }]),
    { name: 'To', value: 'recipient@example.com' },
    { name: 'Subject', value: 'Inspection' },
  ];
  const text = options.text ?? 'Hello';
  const parts: gmail_v1.Schema$MessagePart[] = [
    { mimeType: 'text/plain', body: { data: encoded(text) } },
  ];
  if (options.html !== undefined) {
    parts.push({ mimeType: 'text/html', body: { data: encoded(options.html) } });
  }

  return {
    id: 'r-1',
    message: {
      id: 'm-1',
      threadId: 'thread-1',
      payload: { mimeType: 'multipart/alternative', headers, parts },
    },
  };
}

function fakeGmail(options: {
  draft?: gmail_v1.Schema$Draft;
  draftError?: unknown;
  signature?: string;
  settingsError?: unknown;
} = {}) {
  const get = options.draftError
    ? vi.fn().mockRejectedValue(options.draftError)
    : vi.fn().mockResolvedValue({ data: options.draft ?? draftFixture() });
  const list = options.settingsError
    ? vi.fn().mockRejectedValue(options.settingsError)
    : vi.fn().mockResolvedValue({
        data: {
          sendAs: [{
            sendAsEmail: 'sender@example.com',
            isDefault: true,
            signature: options.signature ?? '<p>Signature</p>',
          }],
        },
      });
  const update = vi.fn().mockResolvedValue({ data: { id: 'r-1' } });

  return {
    gmail: { users: { drafts: { get, update }, settings: { sendAs: { list } } } } as unknown as gmail_v1.Gmail,
    get,
    list,
    update,
  };
}

function inspection(result: Awaited<ReturnType<typeof handleInspectDraft>>) {
  return JSON.parse(result.content[0].text);
}

async function rejectedError(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error('Expected promise to reject');
}

describe('handleInspectDraft', () => {
  it('returns READY and fetches exactly one full draft without mutating Gmail', async () => {
    const fixture = fakeGmail({
      draft: draftFixture({ html: '<p>Hello</p><p>Signature</p>' }),
    });

    const result = await handleInspectDraft(fixture.gmail, {
      draftId: 'r-1',
      requireSignature: true,
      requireHtml: true,
      checkRemoteSignatureAssets: false,
    });

    expect(inspection(result).verdict).toBe('READY');
    expect(result).not.toHaveProperty('isError');
    expect(fixture.get).toHaveBeenCalledWith({ userId: 'me', id: 'r-1', format: 'full' });
    expect(fixture.update).not.toHaveBeenCalled();
  });

  it('returns ordinary acceptance failures as NOT_READY without MCP error semantics', async () => {
    const fixture = fakeGmail({ draft: draftFixture() });

    const result = await handleInspectDraft(fixture.gmail, { draftId: 'r-1', requireHtml: true });

    expect(inspection(result)).toMatchObject({
      verdict: 'NOT_READY',
      errors: ['Draft does not contain an HTML body'],
    });
    expect(result).not.toHaveProperty('isError');
  });

  it('returns NOT_READY for a required signature when From is absent', async () => {
    const fixture = fakeGmail({ draft: draftFixture({ from: null }) });

    const result = await handleInspectDraft(fixture.gmail, { draftId: 'r-1', requireSignature: true });

    expect(inspection(result)).toMatchObject({ verdict: 'NOT_READY', errors: ['Draft has no From header'] });
    expect(result).not.toHaveProperty('isError');
    expect(fixture.list).not.toHaveBeenCalled();
  });

  it('returns NOT_READY plus a truthful warning when no signature is configured', async () => {
    const fixture = fakeGmail({ signature: '' });

    const result = await handleInspectDraft(fixture.gmail, { draftId: 'r-1', requireSignature: true });
    const parsed = inspection(result);

    expect(parsed.verdict).toBe('NOT_READY');
    expect(parsed.errors).toContain('Required signature HTML was not provided');
    expect(parsed.warnings).toContain('No Gmail send-as signature is configured for this From address');
    expect(result).not.toHaveProperty('isError');
  });

  it.each([
    { code: 401, message: 'token=secret-value' },
    { code: 500, message: 'backend=secret-value' },
  ])('propagates signature lookup auth/service errors with a safe operational message', async settingsError => {
    const fixture = fakeGmail({ settingsError });

    const error = await rejectedError(handleInspectDraft(fixture.gmail, {
      draftId: 'r-1',
      requireSignature: true,
    }));

    expect(error).toBeInstanceOf(DraftOperationalError);
    expect(error.message).toBe('Unable to retrieve the Gmail send-as signature');
    expect(error.message).not.toContain('secret-value');
  });

  it.each([
    [{ code: 401, message: 'token=auth-secret' }, 'Gmail authentication failed while inspecting the draft'],
    [{ response: { status: 403 }, message: 'permission secret' }, 'Gmail authentication failed while inspecting the draft'],
    [{ code: 404, message: 'draft payload secret' }, 'Draft not found'],
  ])('maps draft retrieval failures to safe operational errors', async (draftError, expected) => {
    const fixture = fakeGmail({ draftError });

    const error = await rejectedError(handleInspectDraft(fixture.gmail, { draftId: 'r-1' }));

    expect(error).toBeInstanceOf(DraftOperationalError);
    expect(error.message).toBe(expected);
    expect(error.message).not.toContain('secret');
  });

  it('treats inconsistent schema options as a safe operational error before Gmail access', async () => {
    const fixture = fakeGmail();

    const error = await rejectedError(handleInspectDraft(fixture.gmail, {
      draftId: 'r-1',
      requireSignature: false,
      checkRemoteSignatureAssets: true,
    }));

    expect(error).toBeInstanceOf(DraftOperationalError);
    expect(error.message).toBe('Invalid inspect_draft arguments');
    expect(fixture.get).not.toHaveBeenCalled();
  });
});

describe('handleUpdateDraft', () => {
  it('applies a signature and preserves draft, thread, reply, references, and attachments', async () => {
    const fixture = fakeGmail();
    const captured: EmailMessageArgs[] = [];

    const result = await handleUpdateDraft(fixture.gmail, {
      draftId: 'r-1',
      to: ['recipient@example.com'],
      subject: 'Subject',
      body: 'Hello',
      from: 'Sender <sender@example.com>',
      threadId: 'thread-1',
      inReplyTo: '<message-1@example.com>',
      references: '<root@example.com> <message-1@example.com>',
      attachments: ['report.pdf'],
      includeSignature: true,
    }, {
      applySignature,
      createEmailMessage: args => {
        captured.push(args);
        return 'plain-mime';
      },
      createEmailWithNodemailer: async args => {
        captured.push(args);
        return 'attachment-mime';
      },
    });

    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({
      threadId: 'thread-1',
      inReplyTo: '<message-1@example.com>',
      references: '<root@example.com> <message-1@example.com>',
      attachments: ['report.pdf'],
      mimeType: 'multipart/alternative',
    });
    expect(captured[0].htmlBody).toContain('<p>Signature</p>');
    expect(fixture.update).toHaveBeenCalledWith({
      userId: 'me',
      id: 'r-1',
      requestBody: {
        message: {
          raw: Buffer.from('attachment-mime').toString('base64url'),
          threadId: 'thread-1',
        },
      },
    });
    expect(result.content[0].text).toContain('Signature: applied');
  });
});

describe('renderToolError', () => {
  it('marks operational failures as MCP errors without changing successful inspection results', () => {
    expect(renderToolError(new DraftOperationalError('Draft not found'))).toEqual({
      isError: true,
      content: [{ type: 'text', text: 'Error: Draft not found' }],
    });
  });
});
