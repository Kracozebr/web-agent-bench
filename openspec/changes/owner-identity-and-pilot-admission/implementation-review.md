# Local product implementation and acceptance

Date: 2026-10-25. Scope approval: [approval.md](approval.md).

The actual Next.js UI, Fastify API and PostgreSQL identity/admission store now
exist in `packages/owner-web` and `packages/owner-identity`. All application
installation, builds, migrations, browser checks, Python BDD and replay run in
the [OID Docker runtime](../../../infrastructure/owner-identity/README.md).
The Stitch-derived mock remains a separate design artifact.

## Implemented and observed

- Actual owner sign-in controls call Better Auth through the same-origin API.
  Google callback/state/PKCE uses an isolated provider transport with RS256
  tokens and actual JWT verification. SIWE uses a real ephemeral EOA signature,
  Base chain ID 8453, one-time database challenges and an HttpOnly browser binding.
- The browser issues an invitation under the configured verified administrator,
  activates a different owner, links a wallet, logs out, and signs back in through
  that wallet with the same owner and both identity methods.
- An independent `oid_observer` PostgreSQL role reads the final owner, identity,
  invitation, admission/redemption, policy and audit rows by operation identity.
  It has SELECT privileges, no UPDATE privilege, and read-only transactions.
- Invalid signature/domain/URI/chain/time, unsupported local wallet interface,
  denied/abandoned provider flows, lost browser binding and invalid invitation
  attempts do not establish the denied authority. Caller-supplied wallet email
  does not establish Google ownership.
- Real admin controls change open/closed policy and revoke an unused invitation;
  an ordinary authenticated owner receives a real admin API refusal.
- A separate real browser race for one invitation has one winning admission.
  Its committed response is deliberately lost, the API process is restarted,
  and the original operation is retried through the UI. SQL still has one
  redemption/admission and the competitor stays pending. This local admission
  proof does not establish the missing bonus-ledger observation of OID-SC-003.

Review and runtime matrices found and fixed substantive issues: partial wallet
association commits on conflict, Google linking without current-session binding,
stale invitation expiry during lock waits, a false successful revoke during a
redemption race, future SIWE `Issued At` acceptance, and a Google callback path
which decoded claims without explicitly invoking the available JWT verifier.
The application now invokes the pinned verifier and enforces signed SIWE time
bounds itself. The session foreign keys are retained; sign-out audits pending
link operations rather than weakening relational integrity.

## Acceptance state

The [active-delta report](../../../tests/bdd/changes/owner-identity-and-pilot-admission/acceptance-evidence.json)
is authoritative for the latest per-scenario result. The established local
results are OID-SC-001, OID-SC-002 and OID-SC-011 passed; nine mandatory gates
remain blocked. The acceptance command deliberately exits nonzero for these
blocked mandatory gates. A pytest skip is converted to `blocked` in this report.

| Gates | Missing proof |
| --- | --- |
| OID-SC-003 | Actual bonus ledger/no-auto-credit boundary, despite observed local redemption race/recovery |
| OID-SC-004/005/010 | Actual agent-card, delegated credential, source balances and funding/withdrawal integration |
| OID-SC-006 | Complete identity conflict/cross-session matrix and downstream preservation observations |
| OID-SC-007 | Policy/admission race and preservation of actual agent/ledger histories |
| OID-SC-008 | Complete expiry/foreign/agent authority matrix and actual agent-revocation boundary |
| OID-SC-009 | Actual delegated-agent authority and the complete revocation retry variant |
| OID-SC-012 | Actual dedicated Google project/account and a selected real browser-wallet edition |

The implementation checklist records 13/20 completed tasks separately from
3/12 passed mandatory runtime scenarios. This does not close stage 2 as a whole:
card management, MCP/preflight, handoff and task execution belong to later
approved slices. No sync/archive or production-readiness claim is made.

## Reproduction and evidence

From the repository root, after bootstrapping the local secrets and PostgreSQL
as documented by the Docker runtime:

```powershell
docker compose -f infrastructure/owner-identity/compose.yaml build runtime
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web build
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance acceptance
./infrastructure/owner-identity/tool.ps1 python tools/run_bdd_acceptance.py --change owner-identity-and-pilot-admission
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance replay -- all
```

Captures live in `artifacts/runs/acceptance/OID-SC-*/runs/<uuid>/`; each scenario's
top-level manifest indexes immutable runs. Manifests retain safe raw artifact
paths/hashes, source hashes before/after, runtime/browser versions and the declared
local boundary. Earlier partial smoke claims are superseded by the latest index;
the old capture directories are retained rather than rewritten or deleted.
Replay checks hashes, contract inventories and semantic predicates derived from
browser/SQL/provider primitives. It performs no network, authentication or domain
mutation. Producer flags alone cannot establish acceptance.

Google credentials, cookies, invitation values, raw wallet signatures and signing
keys are omitted from evidence. The acceptance fixture uses a fresh secret and
local test credentials per run; no external provider or real wallet extension
is represented by it. Source changes during a run block its result. Worktree
provenance remains explicitly dirty until the owner chooses to commit this work.
