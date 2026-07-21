import { describe, expect, it } from 'vitest';
import { SendEmailSchema, UpdateDraftSchema } from './tools.js';
import {
  applySignature,
  NO_SIGNATURE_WARNING,
  plainTextToHtml,
  type EmailMessageArgs,
} from './signature.js';

function clientArgs(): EmailMessageArgs {
  return {
    to: ['recipient@example.com'],
    subject: 'Subject',
    body: 'Hello\n\nRegards',
    includeSignature: true,
  };
}

function validUpdate(overrides: Record<string, unknown> = {}) {
  return {
    draftId: 'r-1',
    to: ['recipient@example.com'],
    subject: 'Subject',
    body: 'Hello',
    ...overrides,
  };
}

function fakeGmail(signature: string, aliases = [{
  sendAsEmail: 'default@example.com',
  isDefault: true,
  signature,
}]) {
  return {
    users: {
      settings: {
        sendAs: {
          list: async () => ({ data: { sendAs: aliases } }),
        },
      },
    },
  } as any;
}

function fakeGmailFailure(kind: 'missing' | 'error') {
  if (kind === 'error') {
    return {
      users: {
        settings: {
          sendAs: {
            list: async () => { throw new Error('unavailable'); },
          },
        },
      },
    } as any;
  }

  return fakeGmail('');
}

describe('signature application', () => {
  it('escapes plain text and preserves paragraph structure', () => {
    expect(plainTextToHtml('Hello & welcome\n\nLine <two>')).toBe(
      '<p>Hello &amp; welcome</p><p>Line &lt;two&gt;</p>'
    );
    expect(plainTextToHtml('A\nB')).toBe('<p>A<br>B</p>');
  });

  it('applies the default send-as signature exactly once', async () => {
    const first = await applySignature(fakeGmail('<table data-wisestamp="1">Sig</table>'), clientArgs());
    expect(first.status).toBe('applied');
    expect(first.args.htmlBody).toContain('data-wisestamp="1"');

    const second = await applySignature(fakeGmail('<table data-wisestamp="1">Sig</table>'), first.args);
    expect(second.status).toBe('already_present');
    expect(second.args.htmlBody?.match(/data-wisestamp/g)).toHaveLength(1);
  });

  it('recognizes a Gmail-reserialized signature without duplicating it', async () => {
    const signature = '<a href="https://example.com/profile?utm=mail" data-wisestamp="1">  Gabriele\nG  </a>';
    const result = await applySignature(fakeGmail(signature), {
      ...clientArgs(),
      htmlBody: '<p>Hello</p><a data-wisestamp=\'1\' href=\'https://example.com/profile#footer\'>Gabriele G</a>',
    });

    expect(result.status).toBe('already_present');
    expect(result.args.htmlBody?.match(/data-wisestamp/g)).toHaveLength(1);
  });

  it('selects a formatted From alias before the default alias', async () => {
    const result = await applySignature(fakeGmail('<p>Default</p>', [
      { sendAsEmail: 'default@example.com', isDefault: true, signature: '<p>Default</p>' },
      { sendAsEmail: 'chosen@example.com', signature: '<p>Chosen</p>' },
    ]), {
      ...clientArgs(),
      from: 'Gabriele <chosen@example.com>',
    });

    expect(result.status).toBe('applied');
    expect(result.args.htmlBody).toContain('<p>Chosen</p>');
    expect(result.args.htmlBody).not.toContain('<p>Default</p>');
  });

  it.each(['missing', 'error'] as const)('returns %s instead of claiming success', async expected => {
    const result = await applySignature(fakeGmailFailure(expected), clientArgs());

    expect(result.status).toBe(expected);
    expect(result.warning).toBeTruthy();
    if (expected === 'missing') expect(result.warning).toBe(NO_SIGNATURE_WARNING);
  });
});

describe('update draft signature wiring', () => {
  it('accepts includeSignature and defaults it exactly like send_email', () => {
    expect(UpdateDraftSchema.parse(validUpdate({ includeSignature: true })).includeSignature).toBe(true);
    expect(UpdateDraftSchema.parse(validUpdate()).includeSignature).toBe(false);
    expect(UpdateDraftSchema.shape.includeSignature.description)
      .toBe(SendEmailSchema.shape.includeSignature.description);
  });
});
