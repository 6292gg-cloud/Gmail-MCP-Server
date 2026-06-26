# Experiment: gmail-mcp-fork

**Status:** PRODUCTION INFRASTRUCTURE — do NOT kill

**Promote-or-kill by:** 2026-07-20 (decision: upstream-PR vs permanent-fork only)

## What is this

A fork of `@gongrzhe/server-gmail-autoauth-mcp` with a `--tool-prefix` flag added to solve the multi-instance tool-name collision. Both Gmail MCPs (`gmail-personal` and `gmail-info`) run off this fork. The `--tool-prefix` flag is live and required for multi-account operation.

## This is NOT a typical experiment

Both production Gmail MCPs depend on this fork. Do not treat the "promote-or-kill" date as a decommission deadline — the date is for making the structural decision only.

## Decision by 2026-07-20

Choose one of:
1. **Open upstream PR** — submit the `--tool-prefix` flag to the upstream `gongrzhe/server-gmail-autoauth-mcp` repo; if merged, migrate both MCPs to the upstream version
2. **Permanent fork** — accept this fork as a long-term dependency; relocate the repo from `Sandbox/WIP/gmail-mcp-fork/` to a non-experiment location (e.g. `tools/gmail-mcp/` or a standalone repo)

If keeping permanently as a fork, relocation out of `Sandbox/WIP/` is required at that point.

## Refs

- Fork location: `Sandbox/WIP/gmail-mcp-fork/`
- MCP registrations: `.claude/settings.json` (both `gmail-personal` and `gmail-info` entries)
- Upstream: `https://github.com/gongrzhe/server-gmail-autoauth-mcp`
