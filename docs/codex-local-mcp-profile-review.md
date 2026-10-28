# Codex local MCP compatibility: approved scope and evidence

Status: bounded scope approved and implemented on 2026-10-28; local profile acceptance verified.
This document records the approved profile and bounded runtime evidence below.
It does not close the full AAP/BRL scenario gates; the active deltas and approval
addenda remain authoritative.

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
profile on 2026-10-28; the AAP and BRL approval addenda record the scope.
The bounded runtime acceptance is recorded below; full scenario gates remain open.

## Implemented profile and actual local acceptance, 28 October

`OID_MCP_TRANSPORT_PROFILE=codex-local-manual-2025-06-18` selects the SDK 2.4.0
stateless legacy adapter only for a resolved manual credential in the verified
local BEF coordinator, development/test mode and loopback HTTP runtime. The
strict 2026-07-28 transport remains the default. OAuth still uses that strict
profile. Both paths reuse current principal resolution and domain authorization.
The startup coordinator already verifies the local fork; no server.ts change
was needed. Existing task action/executor source pins remain unchanged.

Actual owner-UI capture `7ca6d301-d862-42f5-bd61-8463f45785b4`:
`artifacts/runs/genuine-ranked-worker-owner-run/7ca6d301-d862-42f5-bd61-8463f45785b4/capture.json`,
SHA-256 `5a53271b000520d32c880a840ed8bf14870147622a008fec4ae02187e773aa57`.
Run `2b312199-b6b1-4102-84b8-8daa41e5e62b` used isolated database
`oid_acceptance_7ca6d301d86242f5bd618463f45785b4`; all 304 source inputs stayed stable.
The `bdd.codexProfile` observation verified all 17 scoped checks:

- Pinned real Codex CLI 0.165.0 listed tools, performed allowed free preflight,
  then accepted the actual owner-created intent through MCP.
- Wrong origin, protocol, client and agent binding were rejected; SDK 2.4.0's
  modern 2026-07-28 transport connected and replayed acceptance to the same run.
- HTTP replay also returned that run; read-only financial snapshots stayed equal.
- The real owner Agents page revoked access. `oid_observer` read-only queries
  confirmed generation/revision increments and grant revocation.
- Previous bearer requests returned HTTP/MCP 401. The real Codex revocation probe
  observed exactly one upstream initialize response with 401 and WWW-Authenticate
  through an ephemeral loopback relay, with zero tool calls/actions. Only bounded
  status/count metadata and hashes were retained, never bearer values or raw stderr.
- The completed run and its debit remained unchanged after revocation.

The deterministic reference actor separately executed all 12 tasks through the
server worker; the Codex fixture is a transport/authorization check, not an LLM
benchmark score. External model calls were zero. This is local-fork evidence only.
The full BRL-SC-025 matrix and other mandatory MVP gates remain unfinished.

Final Docker checks: backend build passed, configuration/profile tests 5/5,
Codex adapter tests 11/11 and public selection tests 4/4, without skips.
The earlier full12 capture `ff402dbb-7271-4436-8bce-1e92a17c6751` retained a blocked
profile result (16/17): it lacked direct native 401 observation. It was not
rewritten as a pass; the newer capture supplies that missing evidence.
Independent post-stop reconciliation verified 16/16 checks against `oid_observer`
and `bef_observer` read-only transactions and 2,256 original evidence files.
All 12 outcomes were known, original leases fenced, dispatch claim released,
execution slots empty, and exactly one reserve plus one debit of 1,000,000 units
was recorded. Aggregate remained `1285/13`; completion is distinct from perfect
benchmark performance (S2 is partial).

Report: same capture directory, `poststop-reconciliation.json`, SHA-256
`2fa7b7bfc667957bae7cb5de0982cf50acac56947fef6a97eb64c1ca6b60e068`.
The retained read-only verifier `poststop-reconciliation.mjs` has SHA-256
`412c866bbcd0664eacaaf21d47f71fb6b877c8ffeee64a95f335e29cc5cec4a0`.