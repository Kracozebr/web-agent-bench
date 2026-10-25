# Owner identity acceptance

This package drives local owner journeys through the browser UI, the running
owner API, and PostgreSQL. Its database observer uses a separate read-only
connection. Browser cookies, invitation values, OAuth data, wallet signatures,
and signing keys stay in process memory and are never written to evidence.

The local acceptance gate is separate from the external provider gate. OID-SC-012
is recorded as `blocked` by this runner; it does not open Google or a browser
wallet account. Missing downstream agent-access, billing, or ledger boundaries
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
```

The runner starts the actual owner API and production Next server in the same
container, then drives browser controls through the same-origin proxy. The
runner also exercises private agent-card creation/edit and permission settings,
including foreign-owner denial, idempotent retry and a two-tab revision race.
The runner also exercises manual credential issuance, response loss/replacement,
expiry, live policy reload and durable credential revoke across API restart.
AAP-SC-004 passes only when its eight named observations/negatives derive from
actual browser/HTTP/SQL evidence. Fifteen other full AAP gates remain blocked
on OAuth, domain, lifecycle and client boundaries. Stop the dev
container before building/running production acceptance to avoid sharing writes
to Next.js `.next`; restart it afterward.

The parent BDD command replays each scenario's sanitized observation manifest.
Scenario directories retain individual runs and SHA-256 hashes; replay performs
no authentication, invitation, policy, or product operation. A blocked result
is evidence of a remaining gate, not a passing acceptance.
