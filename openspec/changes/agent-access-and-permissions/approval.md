# Implementation approval

Date: 2026-10-25 (Europe/Moscow).

The owner replied “ок, подходит такой сценарий” after the
[AAP entry review](../../../docs/aap-entry-review.md) and a plain-language
explanation of private agent cards, four initially disabled independent action
permissions, browser/manual connections, show-once credentials, current-policy
enforcement and explicit agent-wide revocation distinct from browser logout.

This approves incremental implementation of the unchanged AAP-REQ-001–008 and
AAP-SC-001–016 package, beginning with private cards and owner policy. Existing
assertions, negative variants, durable effects and mandatory boundaries remain.
Approved defaults: private new cards with owner-declared/unverified metadata;
four action permissions disabled until owner selection; independent monetary
controls; show-once high-entropy manual credentials stored only as verifiers,
replacement rather than plaintext recovery; fixed grant identity/resource bounds
with current business policy checked at operation time; explicit global revoke.

Versions, numerical lifetimes/limits and actual client editions must be pinned
before their implementation/acceptance. They were not selected by this reply.
Missing coordinator/forum/ledger/payment/client environments remain blocked;
cards/policy alone cannot pass the full AAP package or replace those boundaries.
No approval for unrelated capability changes, real-funds operations or production
activation is inferred. New scenarios or changed assertions require renewed review.

Approval authorizes implementation and acceptance; it is not evidence of a pass.

## Addendum: local Codex manual-bearer compatibility profile

Date: 2026-10-28.

The owner approved the bounded revision recorded in
[codex-local-mcp-profile-review.md](../../../docs/codex-local-mcp-profile-review.md):
Codex CLI 0.165.0 using MCP 2025-06-18 through the existing owner-issued manual
bearer route, explicitly enabled only for the local BEF loopback profile. The
default remains MCP 2026-07-28 with legacy handling rejected. No OAuth legacy
profile, other protocol version, client identity-header trust or authority change
is approved. Existing owner/agent/resource/grant and current-policy checks,
permissions, spending limits, revocation and domain idempotency remain unchanged.

This addendum selects an implementation/acceptance profile within AAP-SC-013 and
AAP-SC-016; it does not add or change scenario IDs, assertions, negative variants
or runtime contracts. Approval is not acceptance evidence; all actual client and
domain-operation gates remain independently required.
