#!/usr/bin/env node
/**
 * Standalone test for draft lifecycle Gmail API calls.
 * Validates the same API operations our new MCP tools (send_draft / delete_draft / update_draft)
 * will perform — running directly against the Gmail API with the MCP's OAuth credential.
 *
 * Why standalone: the running MCP server holds the OLD compiled code in memory.
 * We can't exercise the new tools without restarting Claude Code, but we CAN
 * verify the underlying API behavior the new handlers depend on.
 *
 * Scenarios:
 *  1. Create draft → verify it exists in Drafts
 *  2. Update draft → verify subject changed, ID unchanged
 *  3. Send draft → verify message in Sent, draft removed from Drafts
 *  4. Create another draft → verify exists
 *  5. Delete draft → verify removed
 *
 * Cleanup: the sent message from step 3 is removed at the end so the inbox stays clean.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';

const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = path.join(CONFIG_DIR, 'credentials.json');

// Marker for easy identification + manual cleanup if something goes sideways
const STAMP = new Date().toISOString().replace(/[:.]/g, '-');
const MARKER = `[MCP-DRAFT-LIFECYCLE-TEST-${STAMP}]`;
const SELF = 'luca.ambrosini@sartiq.com';

function loadAuth() {
    const keysFile = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
    const keys = keysFile.installed || keysFile.web;
    const credFile = JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
    const tokens = credFile.tokens || credFile;
    const client = new OAuth2Client(keys.client_id, keys.client_secret, 'http://localhost:3000/oauth2callback');
    client.setCredentials(tokens);
    return client;
}

function buildRaw({ to, subject, body, from }) {
    const lines = [
        `From: ${from}`,
        `To: ${to}`,
        `Subject: ${subject}`,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        '',
        body,
    ];
    return Buffer.from(lines.join('\r\n')).toString('base64')
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const results = [];
function record(name, ok, detail = '') {
    results.push({ name, ok, detail });
    const tag = ok ? 'PASS' : 'FAIL';
    console.log(`[${tag}] ${name}${detail ? ' — ' + detail : ''}`);
}

async function main() {
    const auth = loadAuth();
    const gmail = google.gmail({ version: 'v1', auth });

    // --- Scenario 1: create draft ---
    const subj1 = `${MARKER} scenario 1 initial`;
    const create = await gmail.users.drafts.create({
        userId: 'me',
        requestBody: { message: { raw: buildRaw({ to: SELF, subject: subj1, body: 'initial body', from: SELF }) } },
    });
    const draftId = create.data.id;
    record('1. drafts.create returns ID', !!draftId, `draftId=${draftId}`);

    // Verify draft exists
    const listed1 = await gmail.users.drafts.list({ userId: 'me', q: MARKER, maxResults: 5 });
    const found1 = (listed1.data.drafts || []).some(d => d.id === draftId);
    record('1b. draft visible in drafts.list', found1);

    // --- Scenario 2: update draft ---
    const subj2 = `${MARKER} scenario 2 updated`;
    await gmail.users.drafts.update({
        userId: 'me',
        id: draftId,
        requestBody: { message: { raw: buildRaw({ to: SELF, subject: subj2, body: 'updated body', from: SELF }) } },
    });
    // Read back and confirm subject changed; ID unchanged
    const fetched = await gmail.users.drafts.get({ userId: 'me', id: draftId, format: 'metadata' });
    const subjHdr = (fetched.data.message?.payload?.headers || []).find(h => h.name === 'Subject')?.value;
    record('2. drafts.update changes subject', subjHdr === subj2, `subject=${subjHdr}`);
    record('2b. drafts.update preserves draft ID', fetched.data.id === draftId);

    // --- Scenario 3: send draft (the ghost-fix) ---
    const sent = await gmail.users.drafts.send({ userId: 'me', requestBody: { id: draftId } });
    const sentMessageId = sent.data.id;
    record('3. drafts.send returns message ID', !!sentMessageId, `msgId=${sentMessageId}`);

    // Verify draft is gone from Drafts
    const listed3 = await gmail.users.drafts.list({ userId: 'me', q: MARKER, maxResults: 5 });
    const draftsLeft = (listed3.data.drafts || []).map(d => d.id);
    const ghostGone = !draftsLeft.includes(draftId);
    record('3b. draft removed from Drafts after send', ghostGone, `remaining=${JSON.stringify(draftsLeft)}`);

    // Verify message exists in Sent
    const sentList = await gmail.users.messages.list({ userId: 'me', q: `${MARKER} in:sent`, maxResults: 5 });
    const inSent = (sentList.data.messages || []).some(m => m.id === sentMessageId);
    record('3c. message appears in Sent', inSent);

    // --- Scenario 4 + 5: create another draft, delete it ---
    const subj4 = `${MARKER} scenario 4 for-delete`;
    const create2 = await gmail.users.drafts.create({
        userId: 'me',
        requestBody: { message: { raw: buildRaw({ to: SELF, subject: subj4, body: 'delete me', from: SELF }) } },
    });
    const draftId2 = create2.data.id;
    record('4. second draft created', !!draftId2, `draftId=${draftId2}`);

    await gmail.users.drafts.delete({ userId: 'me', id: draftId2 });
    const listed5 = await gmail.users.drafts.list({ userId: 'me', q: MARKER, maxResults: 5 });
    const stillThere = (listed5.data.drafts || []).some(d => d.id === draftId2);
    record('5. drafts.delete removes the draft', !stillThere);

    // --- Cleanup: trash the test message and any stray drafts ---
    let cleaned = 0;
    try {
        await gmail.users.messages.trash({ userId: 'me', id: sentMessageId });
        cleaned++;
    } catch (e) { /* ignore */ }
    // Also trash any received copy (since we sent to self, an inbox copy may exist)
    try {
        const inboxCopies = await gmail.users.messages.list({ userId: 'me', q: `${MARKER} in:inbox`, maxResults: 5 });
        for (const m of inboxCopies.data.messages || []) {
            await gmail.users.messages.trash({ userId: 'me', id: m.id });
            cleaned++;
        }
    } catch (e) { /* ignore */ }
    console.log(`\nCleanup: trashed ${cleaned} test message(s).`);

    // --- Summary ---
    const fails = results.filter(r => !r.ok);
    console.log(`\n${results.length - fails.length}/${results.length} checks passed.`);
    if (fails.length) {
        console.log('FAILURES:');
        for (const f of fails) console.log(`  - ${f.name}: ${f.detail}`);
        process.exit(1);
    }
    console.log('All draft-lifecycle API calls behave as expected. Safe to wire up MCP tools.');
}

main().catch(err => {
    console.error('Test run threw:', err.message);
    if (err.errors) console.error(JSON.stringify(err.errors, null, 2));
    process.exit(2);
});
