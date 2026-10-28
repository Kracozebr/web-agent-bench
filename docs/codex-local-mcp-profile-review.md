# Codex local MCP compatibility: approved scope and evidence

Status: bounded scope approved on 2026-10-28; implementation and runtime acceptance remain separate.
This document records the observations and approved profile. It is not evidence
that the server supports the profile or that any AAP/BRL gate has passed. The
active AAP/BRL deltas and approval addenda remain authoritative.

## Observed boundary

Actual Codex CLI `@openai/codex@0.165.0` requests MCP `2025-06-18` as
`codex-mcp-client` version `0.165.0`. Two local non-owner fixture runs observed
that initialization and one native MCP tool call, with zero owner actions.
The official npm latest tag was also `0.165.0` when checked on 28 October.

The owner server in `packages/owner-identity/src/agents.ts` permits only
`2026-07-28` and configures `legacy: "reject"`. Actual owner-bound capture
`fcacd046-88dd-4c9e-90f4-a634125faa28` stopped at native MCP startup with
`mcp_handshake_error` / `mcp_transport_error`, before accepting its intent.
Raw capture SHA-256:
`f32e75d1677ae3647e32e3e6c72998f1b7195b1f1e068765d9fd90037d5a851a`.
A permissive fixture returning the newer version label still allowed one native
CLI tool call, so the numeric label difference alone is not the causal proof.
The actual server SDK `2.4.0`, configured exactly with the selected strict profile,
rejected the CLI's JSON-RPC `initialize` with HTTP 400 before any tool call. The
`mcp-protocol-version`, `mcp-method` and `mcp-name` headers were absent. This
isolates the legacy transport-format boundary; no owner route was configured in
that diagnostic. An independent `oid_observer` read-only check of the real failed
owner capture found zero runs, slots, reservations and reserve/debit entries.
The client stderr was not retained; only bounded byte counts, hashes and
allowlisted error classes are stored.

AAP design explicitly requires revising scope if selected clients need an
additional protocol profile: `openspec/changes/agent-access-and-permissions/design.md`.
The captured default-profile rejection remains the expected default behavior; it
is not a successful Codex handoff. The approved local profile is a separate,
explicit compatibility path and still requires actual owner-bound acceptance.

## Approved bounded revision

1. Add an explicitly selected local-only compatibility profile for Codex CLI
   `0.165.0`, MCP `2025-06-18`, and the existing owner-issued manual bearer route.
   Keep the existing `2026-07-28` profile and its rejection behavior as the default.
2. Gate compatibility by an explicit local BEF configuration and loopback
   origin/host. Permit only the declared version in that profile. Do not add an
   OAuth legacy profile, broaden metadata fetches, trust client identity headers,
   or accept other unsupported protocol versions.
3. Reuse the same current owner/agent/resource/grant checks, business permissions,
   spending limits, revocation and domain idempotency. Transport compatibility
   must not confer new authority, alter quote/debit rules or carry credentials
   in links, prompts, source files or evidence.
4. Configure the SDK's supported compatibility handling explicitly rather than
   rewriting request/response version labels. Expected files are `config.ts`,
   `agents.ts` and `server.ts`, plus local acceptance configuration and client
   captures. Task action/executor semantics and their minimum-action pins stay
   outside this revision.
5. Record the selected profile in the existing AAP/BRL proposal, design, BDD
   design and approval documents. Keep existing scenario IDs and assertions;
   this scope adds no scenario, variant or normative claim.

## Required actual acceptance

Run only in the isolated local BEF fork with synthetic assets and temporary keys.
Use the actual pinned Codex CLI to list tools, perform free preflight and accept
a real owner-UI intent. Independently verify one committed intent/run/reservation
link and one admission identity; exercise HTTP/MCP retries and owner revocation
without widening authority or repeating an economic effect. Prove rejection of
wrong origin/resource/card, unsupported versions and legacy access outside the
selected local profile. Keep default-profile rejection and existing OAuth tests.

The full12 server-worker result remains a separate execution measurement.
Copy fallback, non-responding client, approvals, back/reload/double-click and
stale review still need their BRL-SC-025 observations; compatibility alone does
not close that gate or justify a one-click claim. Platform-recovery refunds and
trusted integrity findings remain separate unfinished lifecycle requirements.

Approval record: the owner approved only this additional local manual-bearer
profile on 2026-10-28; the AAP and BRL approval addenda record the scope. No
runtime acceptance or scenario-gate pass is claimed here.
