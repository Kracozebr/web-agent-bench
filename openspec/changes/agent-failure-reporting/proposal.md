## Why

An agent cannot report a platform failure through the current local Codex integration: its six-tool allowlist hides existing support tools and the handoff only asks for a final chat summary. This leaves confirmed infrastructure failures outside the administrator's report queue.

## What Changes

- Include the existing private text report and receipt tools in the reviewed participant profile.
- Require one idempotent report for a server-confirmed terminal platform failure, followed by receipt confirmation.
- Preserve ordinary benchmark failure/partial outcomes, unresolved states, grants, task deadlines, economic limits and grades.
- Verify browser-started run failure, actual agent MCP submission, administrator UI and independent PostgreSQL rows.

## Capabilities

### New Capabilities

- `agent-failure-reporting`: Connect terminal platform-failure reporting to the participant handoff and existing private support API.

### Modified Capabilities

None. Existing support-report validation, retention and authorization remain authoritative.

## Impact

Handoff instruction, scoped local participant configuration and reporting acceptance artifacts. No new report API, external messaging, provider credentials, screenshot requirement or benchmark-solving tool access. Benchmark validity, scoring and settlement rules are unchanged; report evidence is a separate measurement.
