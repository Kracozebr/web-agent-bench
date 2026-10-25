# Private card and owner-policy slice

Status: approved incremental implementation, not full AAP acceptance.
The [approval](approval.md) covers the existing sixteen scenarios. Their full
requirements and mandatory dependencies remain unchanged.

## Implemented boundary

The existing owner application now exposes `/agents`: admitted owners create,
list and edit private cards and select four independent permission settings.
Optional client/model/version metadata is explicitly owner-declared and
unverified. New cards default all permissions to false. Profile and policy
revisions are separate; unsupported owner/publication fields reject.

The Fastify API uses the existing Better Auth session and immutable OID owner ID.
PostgreSQL tables `oid_agent`, `oid_agent_policy` and `oid_agent_operation` store
cards, policy and idempotent receipts. Mutations commit their audit in the same
transaction. Foreign IDs return 404; unadmitted owners and unauthenticated or
forged bearer authority cannot create cards. No public profile endpoint or
publication marker authority was added.

Profile and policy writes serialize on the same immutable agent key. The real
two-tab test exposed a PostgreSQL deadlock between operation-row FK key-share
locks and `FOR UPDATE`; `FOR NO KEY UPDATE` preserves serialization and permits
the FK lock. Both requests at policy revision 2 now produce one 200 and one 409,
one new revision and one committed audit, rather than a 500.

## Verified evidence

Docker production build/typecheck and additive migration passed. The integrated
browser capture `54747112-38ab-49cd-90df-bfc85eadbae7` used actual controls for
create, profile update and permission saves. Independent `oid_observer`
SELECT-only snapshots correlated operation IDs to committed card/policy/audit
rows; reload retained settings. Direct HTTP negatives separately checked foreign
read/edit, pending creation, forged publication/credential, stale revision,
idempotent retry and changed-payload conflict. A forged credential is not an
actual issued agent credential and does not prove that future authority boundary.

Source inputs were unchanged during the final capture. AAP immutable raw runs
use `artifacts/runs/acceptance/AAP-SC-*/runs/<uuid>/` with three hashed artifacts
each. Read-only filesystem replay verified all 48 artifacts and seven partial
card facts for SC001/006/014. No credential or domain action is repeated by replay.
The existing OID replay also verified its 60 artifacts.

Semantic AAP audit protects all sixteen approved scenarios. The
[AAP report](../../../tests/bdd/changes/agent-access-and-permissions/acceptance-evidence.json)
records sixteen blocked mandatory gates; pytest skips are mapped to blocked,
and the acceptance command deliberately exits nonzero. Partial card facts do not
pass whole scenarios. The OID report remains three passed / nine blocked.

## Remaining work

No OAuth/MCP server, manual credential, consent/revoke controls, actual agent
verifier, free preflight, run/forum operation, ledger/cap or cancellation effect
is claimed. Historical run snapshots and BLP public-marker integration do not
exist yet. Actual-client editions and protocol/TTL configuration are unpinned.
These remain separate mandatory blockers, including every full AAP scenario.
The next slice is agent-bound connection/credential authority and safe owner
controls, followed by actual domain integration; no stub receipt can replace it.
Sync/archive is not allowed in this state.

## Reproduction

Use only the Docker runtime described in
[the infrastructure README](../../../infrastructure/owner-identity/README.md).
Stop the dev container before the production acceptance build: both currently
share the source-mounted Next.js `.next` directory. Restart it after capture.

```powershell
docker stop web-agent-bench-oid-dev
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-web build
./infrastructure/owner-identity/tool.ps1 pnpm --filter @web-agent-bench/owner-acceptance acceptance
./infrastructure/owner-identity/tool.ps1 python tools/run_bdd_acceptance.py --change agent-access-and-permissions
./infrastructure/owner-identity/tool.ps1 python tools/replay_aap_acceptance.py all
docker start web-agent-bench-oid-dev
```

Captures use the declared local Google transport and synthetic EOA fixture, not
actual Google/browser-extension or third-party MCP client compatibility. Runtime
secrets and raw auth material remain outside evidence and tracked files.
