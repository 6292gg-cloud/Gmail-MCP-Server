import type { gmail_v1 } from 'googleapis';
import { inspectDraft, type DraftInspection } from './draft-inspection.js';
import { applySignature, resolveSignatureHtml } from './signature.js';
import { InspectDraftSchema, UpdateDraftSchema } from './tools.js';
import { createEmailMessage, createEmailWithNodemailer } from './utl.js';

export class DraftOperationalError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DraftOperationalError';
  }
}

interface InspectDraftDependencies {
  inspectDraft: typeof inspectDraft;
  resolveSignatureHtml: typeof resolveSignatureHtml;
}

interface UpdateDraftDependencies {
  applySignature: typeof applySignature;
  createEmailMessage: typeof createEmailMessage;
  createEmailWithNodemailer: typeof createEmailWithNodemailer;
}

export async function handleInspectDraft(
  gmail: gmail_v1.Gmail,
  args: unknown,
  dependencies: Partial<InspectDraftDependencies> = {},
) {
  const inspect = dependencies.inspectDraft ?? inspectDraft;
  const resolveSignature = dependencies.resolveSignatureHtml ?? resolveSignatureHtml;
  let validated: ReturnType<typeof InspectDraftSchema.parse>;

  try {
    validated = InspectDraftSchema.parse(args);
  } catch {
    throw new DraftOperationalError('Invalid inspect_draft arguments');
  }

  let draft: gmail_v1.Schema$Draft;
  try {
    const response = await gmail.users.drafts.get({
      userId: 'me',
      id: validated.draftId,
      format: 'full',
    });
    draft = response.data;
  } catch (error) {
    const status = errorStatus(error);
    if (status === 401 || status === 403) {
      throw new DraftOperationalError('Gmail authentication failed while inspecting the draft');
    }
    if (status === 404) {
      throw new DraftOperationalError('Draft not found');
    }
    throw new DraftOperationalError('Unable to retrieve the Gmail draft');
  }

  const from = draft.message?.payload?.headers?.find(
    header => header.name?.toLowerCase() === 'from'
  )?.value ?? undefined;
  if (validated.requireSignature && !from) {
    return renderInspectionError('Draft has no From header');
  }

  let signature: Awaited<ReturnType<typeof resolveSignatureHtml>> | undefined;
  if (validated.requireSignature) {
    try {
      signature = await resolveSignature(gmail, from);
    } catch {
      throw new DraftOperationalError('Unable to retrieve the Gmail send-as signature');
    }
    if (signature.status === 'error') {
      throw new DraftOperationalError('Unable to retrieve the Gmail send-as signature');
    }
  }

  const inspection = await inspect(draft, validated, signature?.html);
  if (signature?.warning) inspection.warnings.push(signature.warning);
  return renderInspection(inspection);
}

export async function handleUpdateDraft(
  gmail: gmail_v1.Gmail,
  args: unknown,
  dependencies: Partial<UpdateDraftDependencies> = {},
) {
  const apply = dependencies.applySignature ?? applySignature;
  const buildSimpleMessage = dependencies.createEmailMessage ?? createEmailMessage;
  const buildAttachmentMessage = dependencies.createEmailWithNodemailer ?? createEmailWithNodemailer;
  const validatedArgs = UpdateDraftSchema.parse(args);
  const { draftId, ...messageArgs } = validatedArgs;
  const signature = await apply(gmail, messageArgs);
  const signedMessageArgs = signature.args;
  const message = signedMessageArgs.attachments?.length
    ? await buildAttachmentMessage(signedMessageArgs)
    : buildSimpleMessage(signedMessageArgs);
  const raw = Buffer.from(message).toString('base64url');
  const messageRequest: gmail_v1.Schema$Message = { raw };
  if (signedMessageArgs.threadId) messageRequest.threadId = signedMessageArgs.threadId;

  await gmail.users.drafts.update({
    userId: 'me',
    id: draftId,
    requestBody: { message: messageRequest },
  });

  return {
    content: [{
      type: 'text' as const,
      text: `Draft ${draftId} updated successfully (draft ID unchanged, content replaced).\nSignature: ${signature.status}${signature.warning ? `\nWarning: ${signature.warning}` : ''}`,
    }],
  };
}

export function renderToolError(error: unknown) {
  const message = error instanceof Error ? error.message : 'Unknown error';
  return {
    isError: true as const,
    content: [{ type: 'text' as const, text: `Error: ${message}` }],
  };
}

function renderInspectionError(message: string) {
  const inspection: DraftInspection = {
    verdict: 'NOT_READY',
    errors: [message],
    warnings: [],
    headers: { from: '', to: '', cc: '', bcc: '', subject: '', threadId: '' },
    body: { hasText: false, hasHtml: false, preview: '', textParagraphs: 0, htmlBlocks: 0 },
    signature: { required: true, matches: 0, images: 0, assets: [] },
    attachments: [],
  };
  return renderInspection(inspection);
}

function renderInspection(inspection: DraftInspection) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(inspection, null, 2) }],
  };
}

function errorStatus(error: unknown): number | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const direct = 'code' in error ? Number(error.code) : undefined;
  if (Number.isFinite(direct)) return direct;
  if (!('response' in error) || !error.response || typeof error.response !== 'object') return undefined;
  const nested = 'status' in error.response ? Number(error.response.status) : undefined;
  return Number.isFinite(nested) ? nested : undefined;
}
