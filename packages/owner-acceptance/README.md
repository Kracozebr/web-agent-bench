# Owner identity acceptance

This package drives local owner journeys through the browser UI, the running
owner API, and PostgreSQL. Its database observer uses a separate read-only
connection. Browser cookies, invitation values, OAuth data, wallet signatures,
and signing keys stay in process memory and are never written to evidence.

Each capture creates a fresh `oid_acceptance_<run UUID>` database on the Docker
PostgreSQL service. The existing `oid_owner` fixture role creates it and grants
the independent `oid_observer` role SELECT-only access to new tables. The runner
retains the database for inspection and records its name in provenance; it does
not delete or reset the development database. This also isolates persisted JWKS:
each capture uses its own random auth secret, which encrypts that run's JWT keys.
The combined fixture raises auth, SIWE and credential request quotas to 120 per
configured window so repeated UI status reads and the negative matrix fit in one
capture. Provenance records these overrides. Product defaults are unchanged;
this capture makes no production rate-limit acceptance claim.

The local acceptance gate is separate from the external provider gate. OID-SC-012
is recorded as `blocked` by this runner; it does not open Google or a browser
wallet account. Missing downstream agent-access, spending, or coordinator boundaries
are also `blocked`, with a specific reason code.

## Commands

From the repository root in PowerShell, run the acceptance command through the
repository Docker wrapper. The container supplies the pinned Linux runtime,
Chromium, Python BDD dependencies, isolated PostgreSQL URLs, and the separate
read-only observer account.

```powershell
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance acceptance
./infrastructure/owner-identity/tool.ps1 python tools/run_bdd_acceptance.py --change owner-identity-and-pilot-admission
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance replay -- all
./infrastructure/owner-identity/tool.ps1 python tools/run_bdd_acceptance.py --change agent-access-and-permissions
./infrastructure/owner-identity/tool.ps1 python tools/replay_aap_acceptance.py all
./infrastructure/owner-identity/tool.ps1 python tools/run_bdd_acceptance.py --change tester-bonus-billing
./infrastructure/owner-identity/tool.ps1 python tools/replay_tbb_acceptance.py all
```

The runner starts the actual owner API and production Next server in the same
container, then drives browser controls through the same-origin proxy. The
runner also exercises private agent-card creation/edit and permission settings,
including foreign-owner denial, idempotent retry and a two-tab revision race.
The runner also exercises manual credential issuance, response loss/replacement,
expiry, live policy reload and durable credential revoke across API restart.
The OAuth adapter uses an actual separate loopback callback listener, provider
code/PKCE exchange, the official SDK pinned to protocol `2026-07-28`, and
independent SQL observations of grants, code consumption and safe exchange
audits. AAP-SC-002/003/004 can pass only when their approved observations and
negative variants derive from the recorded browser/HTTP/SQL facts. Preflight
alone cannot pass SC015; domain, lifecycle and actual-client boundaries remain
separate mandatory gates. Stop the dev
container before building/running production acceptance to avoid sharing writes
to Next.js `.next`; restart it afterward.

The initial billing slice exercises admin bonus issuance through the browser,
loss of the committed response, restart and same-key retry, unauthorized owner
and agent attempts, invalid terms and immutable-edit rejection. Its independent
`oid_observer` reads lots, source entries, operation receipts and issuance or
rejection audits. TBB-SC-001/002 are the only passable whole billing gates in
this slice. Owner billing and financial-policy UI captures are partial evidence
for TBB-SC-013; actual spending authorization and downstream domain gates remain
blocked. The manifest never converts those partial controls into a full pass.

The parent BDD command replays each scenario's sanitized observation manifest.
Scenario directories retain individual runs and SHA-256 hashes; replay performs
no authentication, invitation, policy, or product operation. A blocked result
is evidence of a remaining gate, not a passing acceptance.
