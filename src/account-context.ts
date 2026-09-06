export interface AccountConfig {
  email?: string;
  label?: string;
  toolPrefix: string;
}

export interface AccountIdentity {
  email: string | null;
  label: string;
  toolPrefix: string;
  verified: boolean;
}

interface ToolResult {
  content: unknown[];
  _meta?: Record<string, unknown>;
}

export class AccountContextError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = 'AccountContextError';
  }
}

function normalizeMailbox(value: string | undefined | null): string | undefined {
  if (!value || /[\r\n]/.test(value)) return undefined;
  const normalized = value.trim().toLowerCase();
  return /^[^\s@<>,;]+@[^\s@<>,;]+\.[^\s@<>,;]+$/.test(normalized) ? normalized : undefined;
}

/** Creates an offline context. Google is contacted only when a tool needs this account. */
export function createAccountContext(
  config: AccountConfig,
  readProfile: () => Promise<{ emailAddress?: string | null }>,
) {
  const expectedEmail = normalizeMailbox(config.email);
  const label = config.label?.replace(/\s+/g, ' ').trim().slice(0, 200) || expectedEmail || 'Gmail account';
  const unverified: AccountIdentity = Object.freeze({ email: null, label, toolPrefix: config.toolPrefix, verified: false });
  let verified: AccountIdentity | undefined;
  let pending: Promise<AccountIdentity> | undefined;

  async function ensureVerified(): Promise<AccountIdentity> {
    if (!expectedEmail) {
      if (config.toolPrefix || config.email?.trim()) {
        throw new AccountContextError(
          'GMAIL_ACCOUNT_CONFIG_REQUIRED',
          'Set GMAIL_ACCOUNT_EMAIL to the intended mailbox for this Gmail instance before using its tools. Do not switch to another mailbox.',
        );
      }
      return unverified;
    }
    if (verified) return verified;
    if (!pending) {
      pending = (async () => {
        let profile: { emailAddress?: string | null };
        try {
          profile = await readProfile();
        } catch {
          // Provider errors may contain request headers or token responses. Never forward them.
          throw new AccountContextError(
            'GMAIL_ACCOUNT_VERIFICATION_FAILED',
            'Cannot verify the configured Gmail account. Check authentication or connectivity for this instance; do not switch mailboxes.',
          );
        }
        if (normalizeMailbox(profile?.emailAddress) !== expectedEmail) {
          throw new AccountContextError(
            'GMAIL_ACCOUNT_MISMATCH',
            `The authenticated Gmail account does not match configured mailbox ${expectedEmail}. Correct this instance's credentials before using its tools.`,
          );
        }
        verified = Object.freeze({ email: expectedEmail, label, toolPrefix: config.toolPrefix, verified: true });
        return verified;
      })().finally(() => {
        // A later call may retry after a temporary outage. No business operation runs on failure.
        pending = undefined;
      });
    }
    return pending;
  }

  return {
    ensureVerified,
    describeTool(description: string): string {
      const account = expectedEmail
        ? `Configured mailbox: ${expectedEmail}. Purpose: ${label}. Identity is verified before access.`
        : config.toolPrefix
          ? 'Mailbox identity is not configured. Set GMAIL_ACCOUNT_EMAIL before using this instance.'
          : 'Legacy unprefixed Gmail instance; mailbox identity is unverified.';
      return `${account} ${description}`;
    },
    async run<T extends ToolResult>(operation: () => Promise<T>): Promise<T & { _meta: Record<string, unknown> }> {
      const account = await ensureVerified();
      const result = await operation();
      return { ...result, _meta: { ...result._meta, gmailAccount: account } };
    },
  };
}

/** Only accept a tool name advertised by this exact server instance. */
export function resolveToolName(rawName: string, prefix: string, known: (name: string) => boolean): string {
  if (prefix && !rawName.startsWith(prefix)) {
    throw new AccountContextError('GMAIL_TOOL_PREFIX_MISMATCH', 'Use the exact tool name advertised by this Gmail instance; do not switch mailbox prefixes.');
  }
  const name = prefix ? rawName.slice(prefix.length) : rawName;
  if (!known(name)) throw new AccountContextError('GMAIL_TOOL_UNAVAILABLE', 'The requested tool is not advertised by this Gmail instance.');
  return name;
}
