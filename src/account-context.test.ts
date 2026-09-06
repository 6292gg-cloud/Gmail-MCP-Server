import { describe, expect, it, vi } from 'vitest';
import { createAccountContext, resolveToolName } from './account-context.js';

const config = {
  email: 'owner@example.com',
  label: 'Owner business correspondence',
  toolPrefix: 'personal_',
};
const identity = { email: 'owner@example.com', label: config.label, toolPrefix: 'personal_', verified: true };

describe('Gmail account verification', () => {
  it('performs no profile request while creating context or describing tools', () => {
    const profile = vi.fn(async () => ({ emailAddress: config.email }));
    const account = createAccountContext(config, profile);
    expect(account.describeTool('Searches email')).toContain('owner@example.com');
    expect(account.describeTool('Searches email')).toContain(config.label);
    expect(account.describeTool('Searches email')).toContain('Configured mailbox');
    expect(profile).not.toHaveBeenCalled();
  });

  it('normalizes the exact mailbox and caches a successful verification', async () => {
    const profile = vi.fn(async () => ({ emailAddress: ' OWNER@Example.COM ' }));
    const account = createAccountContext({ ...config, email: ' Owner@Example.com ' }, profile);
    expect(await account.ensureVerified()).toEqual(identity);
    expect(await account.ensureVerified()).toEqual(identity);
    expect(profile).toHaveBeenCalledTimes(1);
  });

  it('runs a business operation only after matching identity and preserves its content', async () => {
    const account = createAccountContext(config, async () => ({ emailAddress: config.email }));
    const content = [{ type: 'text' as const, text: '{"draftId":"fixture"}' }];
    const operation = vi.fn(async () => ({ content, _meta: { existing: true } }));
    const result = await account.run(operation);
    expect(operation).toHaveBeenCalledTimes(1);
    expect(result.content).toBe(content);
    expect(result._meta).toEqual({ existing: true, gmailAccount: identity });
  });

  it.each(['other@example.com', undefined, '', 'not an email'])('blocks all operations for an unexpected profile %s', async emailAddress => {
    const account = createAccountContext(config, async () => ({ emailAddress }));
    const operation = vi.fn(async () => ({ content: [] }));
    await expect(account.run(operation)).rejects.toMatchObject({ code: 'GMAIL_ACCOUNT_MISMATCH' });
    expect(operation).not.toHaveBeenCalled();
  });

  it('does not expose provider errors and permits a later retry after transient failure', async () => {
    const profile = vi.fn()
      .mockRejectedValueOnce(new Error('Bearer secret-token: private provider payload'))
      .mockResolvedValueOnce({ emailAddress: config.email });
    const account = createAccountContext(config, profile);
    const operation = vi.fn(async () => ({ content: [] }));
    await expect(account.run(operation)).rejects.toMatchObject({
      code: 'GMAIL_ACCOUNT_VERIFICATION_FAILED',
      message: 'Cannot verify the configured Gmail account. Check authentication or connectivity for this instance; do not switch mailboxes.',
    });
    expect(operation).not.toHaveBeenCalled();
    expect(await account.ensureVerified()).toEqual(identity);
    expect(profile).toHaveBeenCalledTimes(2);
  });

  it('deduplicates concurrent first checks before allowing either business operation', async () => {
    let finish!: (value: { emailAddress: string }) => void;
    const profile = vi.fn(() => new Promise<{ emailAddress: string }>(resolve => { finish = resolve; }));
    const account = createAccountContext(config, profile);
    const operation = vi.fn(async () => ({ content: [] }));
    const first = account.run(operation);
    const second = account.run(operation);
    expect(profile).toHaveBeenCalledTimes(1);
    expect(operation).not.toHaveBeenCalled();
    finish({ emailAddress: config.email });
    await Promise.all([first, second]);
    expect(operation).toHaveBeenCalledTimes(2);
    expect(profile).toHaveBeenCalledTimes(1);
  });

  it.each([undefined, '', 'two@example.com,other@example.com', 'owner@example.com\r\nInjected: value'])('requires a valid expected mailbox for prefixed instances: %s', async email => {
    const profile = vi.fn(async () => ({ emailAddress: config.email }));
    const account = createAccountContext({ ...config, email }, profile);
    const operation = vi.fn(async () => ({ content: [] }));
    await expect(account.run(operation)).rejects.toMatchObject({ code: 'GMAIL_ACCOUNT_CONFIG_REQUIRED' });
    expect(operation).not.toHaveBeenCalled();
    expect(profile).not.toHaveBeenCalled();
  });

  it('keeps deliberately unprefixed legacy instances compatible and labels identity unverified', async () => {
    const profile = vi.fn(async () => ({ emailAddress: config.email }));
    const account = createAccountContext({ toolPrefix: '' }, profile);
    const result = await account.run(async () => ({ content: [{ type: 'text' as const, text: 'legacy' }] }));
    expect(result._meta?.gmailAccount).toMatchObject({ email: null, toolPrefix: '', verified: false });
    expect(profile).not.toHaveBeenCalled();
    expect(account.describeTool('Search')).toContain('unverified');
  });

  it('rejects an invalid explicit identity even on an unprefixed instance', async () => {
    const account = createAccountContext({ email: 'invalid', toolPrefix: '' }, async () => ({ emailAddress: config.email }));
    await expect(account.ensureVerified()).rejects.toMatchObject({ code: 'GMAIL_ACCOUNT_CONFIG_REQUIRED' });
  });

  it('checks a fresh context independently rather than sharing identity across instances', async () => {
    const firstProfile = vi.fn(async () => ({ emailAddress: config.email }));
    const secondProfile = vi.fn(async () => ({ emailAddress: 'other@example.com' }));
    await createAccountContext(config, firstProfile).ensureVerified();
    await expect(createAccountContext(config, secondProfile).ensureVerified()).rejects.toMatchObject({ code: 'GMAIL_ACCOUNT_MISMATCH' });
    expect(secondProfile).toHaveBeenCalledTimes(1);
  });
});

describe('strict instance tool names', () => {
  const known = (name: string) => ['search_emails', 'send_email'].includes(name);

  it.each([
    ['personal_', 'personal_search_emails', 'search_emails'],
    ['send_', 'send_send_email', 'send_email'],
    ['', 'search_emails', 'search_emails'],
  ])('accepts an exact advertised name: %s %s', (prefix, rawName, expected) => {
    expect(resolveToolName(rawName, prefix, known)).toBe(expected);
  });

  it.each([
    ['personal_', 'search_emails'],
    ['personal_', 'info_search_emails'],
    ['send_', 'send_email'],
    ['personal_', 'personal_unknown'],
  ])('rejects a name that is not advertised by this instance: %s %s', (prefix, rawName) => {
    expect(() => resolveToolName(rawName, prefix, known)).toThrow();
  });
});
